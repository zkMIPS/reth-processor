//! Arena-backed Merkle Patricia trie for the guest.
//!
//! The guest used to deserialize the witness as a tree of boxed [`MptNode`]s
//! (one heap allocation and two ~112-byte copies per node, 16 of them per
//! branch) and then RLP-encode and keccak every node again to check the state
//! root.  On a reth block that was ~37 M cycles of decoding plus ~31 M of
//! hashing for ~9.6 K nodes — a third of the block.
//!
//! Here the host ships each trie as a *preorder stream* of raw RLP nodes
//! ([`WitnessState`]), and the guest builds an [`ArenaTrie`] from it in one
//! pass: nodes live in one `Vec`, children are indices, every node is
//! keccak-checked exactly once against the digest its parent carries (the
//! root against the anchor), and the verified digest is kept as the node's
//! reference so the state-root pass only re-hashes what the block mutated.
//! No per-node allocation of children, no hash-map lookups.
//!
//! [`MptNode`] stays the host-side representation; it is also the test
//! oracle for this module.

use alloy_primitives::{map::HashMap, Bytes, B256, U256};
use alloy_rlp::Encodable;
use core::mem;
use reth_trie::{HashedPostState, HashedStorage, TrieAccount, EMPTY_ROOT_HASH};
use serde::{Deserialize, Serialize};

use super::mpt::{
    keccak, lcp, prefix_nibs, to_encoded_path, to_nibs, Error, MptNode, MptNodeData,
    MptNodeReference, RlpBytes, EMPTY_ROOT,
};

/// Stream tag: the referenced node is not part of the witness (stays a digest).
const TAG_DIGEST: u8 = 0;
/// Stream tag: a node follows as `varint(len) || rlp`.
const TAG_NODE: u8 = 1;

/// The state tries in witness form: for the state trie and every storage
/// trie, the root hash and a preorder stream of raw RLP nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessState {
    pub state_root: B256,
    pub state_nodes: Bytes,
    /// `(hashed address, storage root, preorder node stream)`, sorted by
    /// address so the input bytes are reproducible.
    pub storage: Vec<(B256, B256, Bytes)>,
}

// ---------------------------------------------------------------------------
// Host side: MptNode -> preorder stream
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: usize) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn is_hashed(node: &MptNode) -> bool {
    matches!(node.reference(), MptNodeReference::Digest(_))
}

/// Emit `node` (which its parent references by digest, or the root) and,
/// recursively, every digest-referenced descendant, in preorder.  Children
/// inlined in their parent's RLP need no entry: an inline node cannot carry a
/// digest child, so its whole subtree is inside the parent's bytes.
fn emit_node(node: &MptNode, out: &mut Vec<u8>) {
    match node.as_data() {
        MptNodeData::Digest(_) => out.push(TAG_DIGEST),
        _ => {
            let rlp = node.to_rlp();
            out.push(TAG_NODE);
            put_varint(out, rlp.len());
            out.extend_from_slice(&rlp);
            emit_children(node, out);
        }
    }
}

fn emit_children(node: &MptNode, out: &mut Vec<u8>) {
    match node.as_data() {
        MptNodeData::Branch(children) => {
            for child in children.iter().flatten() {
                if is_hashed(child) {
                    emit_node(child, out);
                } else {
                    emit_children(child, out);
                }
            }
        }
        MptNodeData::Extension(_, child) => {
            if is_hashed(child) {
                emit_node(child, out);
            } else {
                emit_children(child, out);
            }
        }
        _ => {}
    }
}

/// The preorder node stream of a trie rooted at `root`.
pub fn witness_stream(root: &MptNode) -> Bytes {
    let mut out = Vec::new();
    emit_node(root, &mut out);
    out.into()
}

// ---------------------------------------------------------------------------
// Guest side: arena trie
// ---------------------------------------------------------------------------

type NodeId = u32;
const NONE: NodeId = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Null,
    /// Compact-encoded path (as in the RLP) and the value.
    Leaf(Vec<u8>, Vec<u8>),
    /// Compact-encoded path and the child.
    Extension(Vec<u8>, NodeId),
    Branch([NodeId; 16]),
    Digest(B256),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ref {
    /// Encodings shorter than 32 bytes are inlined by the parent.
    Bytes(Vec<u8>),
    Digest(B256),
}

impl Ref {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Ref::Bytes(b) => out.extend_from_slice(b),
            Ref::Digest(d) => {
                out.push(alloy_rlp::EMPTY_STRING_CODE + 32);
                out.extend_from_slice(d.as_slice());
            }
        }
    }
    fn length(&self) -> usize {
        match self {
            Ref::Bytes(b) => b.len(),
            Ref::Digest(_) => 33,
        }
    }
}

/// A Merkle Patricia trie whose nodes live in one arena.
#[derive(Debug, Clone)]
pub struct ArenaTrie {
    nodes: Vec<Node>,
    /// Cached reference of each node; `None` after a mutation on its path.
    refs: Vec<Option<Ref>>,
    root: NodeId,
}

impl Default for ArenaTrie {
    fn default() -> Self {
        Self { nodes: vec![Node::Null], refs: vec![None], root: 0 }
    }
}

struct Stream<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Stream<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::WitnessFormat("truncated stream"))?;
        self.pos += 1;
        Ok(b)
    }
    fn varint(&mut self) -> Result<usize, Error> {
        let mut v = 0usize;
        let mut shift = 0;
        loop {
            let b = self.byte()?;
            v |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 28 {
                return Err(Error::WitnessFormat("varint too long"));
            }
        }
    }
    fn node(&mut self) -> Result<&'a [u8], Error> {
        let len = self.varint()?;
        let bytes = self
            .buf
            .get(self.pos..self.pos + len)
            .ok_or(Error::WitnessFormat("truncated node"))?;
        self.pos += len;
        Ok(bytes)
    }
}

/// Split one RLP item off the front of `buf`: (header, payload, whole item).
#[inline]
fn take_item<'a>(
    buf: &mut &'a [u8],
) -> Result<(alloy_rlp::Header, &'a [u8], &'a [u8]), alloy_rlp::Error> {
    let start = *buf;
    let header = alloy_rlp::Header::decode(buf)?;
    let payload = buf.get(..header.payload_length).ok_or(alloy_rlp::Error::InputTooShort)?;
    *buf = &buf[header.payload_length..];
    let whole = &start[..start.len() - buf.len()];
    Ok((header, payload, whole))
}

impl ArenaTrie {
    /// Build the trie from its root hash and preorder node stream, checking
    /// every node's keccak against the digest that references it.
    pub fn from_stream(root: B256, stream: &[u8]) -> Result<Self, Error> {
        let mut trie = ArenaTrie {
            nodes: Vec::with_capacity(stream.len() / 48 + 8),
            refs: Vec::with_capacity(stream.len() / 48 + 8),
            root: NONE,
        };
        let mut s = Stream { buf: stream, pos: 0 };
        let id = trie.build(&mut s, root)?;
        if s.pos != stream.len() {
            return Err(Error::WitnessFormat("trailing bytes"));
        }
        trie.root = id;
        Ok(trie)
    }

    #[inline]
    fn push(&mut self, node: Node, r: Option<Ref>) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(node);
        self.refs.push(r);
        id
    }

    /// Next stream entry, which the parent references by `expected`.
    fn build(&mut self, s: &mut Stream<'_>, expected: B256) -> Result<NodeId, Error> {
        match s.byte()? {
            TAG_DIGEST => Ok(self.push(Node::Digest(expected), Some(Ref::Digest(expected)))),
            TAG_NODE => {
                let bytes = s.node()?;
                if keccak(bytes) != expected.0 {
                    return Err(Error::WitnessNodeMismatch(expected));
                }
                let r = if bytes.len() < 32 {
                    Ref::Bytes(bytes.to_vec())
                } else {
                    Ref::Digest(expected)
                };
                let mut buf = bytes;
                let (header, payload, _) = take_item(&mut buf)?;
                if !buf.is_empty() {
                    return Err(Error::WitnessFormat("node has trailing bytes"));
                }
                self.decode_item(header, payload, r, s)
            }
            _ => Err(Error::WitnessFormat("bad tag")),
        }
    }

    /// A child item inside a node's RLP: absent, a digest (whose node is the
    /// next stream entry), or an inline node.
    fn child(
        &mut self,
        header: alloy_rlp::Header,
        payload: &[u8],
        whole: &[u8],
        s: &mut Stream<'_>,
    ) -> Result<NodeId, Error> {
        if header.list {
            return self.decode_item(header, payload, Ref::Bytes(whole.to_vec()), s);
        }
        match payload.len() {
            0 => Ok(NONE),
            32 => self.build(s, B256::from_slice(payload)),
            _ => Err(alloy_rlp::Error::UnexpectedLength.into()),
        }
    }

    /// Decode one node item into the arena.
    fn decode_item(
        &mut self,
        header: alloy_rlp::Header,
        payload: &[u8],
        r: Ref,
        s: &mut Stream<'_>,
    ) -> Result<NodeId, Error> {
        if !header.list {
            return match payload.len() {
                0 => Ok(self.push(Node::Null, Some(r))),
                _ => Err(alloy_rlp::Error::UnexpectedString.into()),
            };
        }
        // count items (2 = leaf/extension, 17 = branch)
        let mut rest = payload;
        let mut items = 0usize;
        while !rest.is_empty() {
            take_item(&mut rest)?;
            items += 1;
        }
        let mut rest = payload;
        match items {
            2 => {
                let (h, path, _) = take_item(&mut rest)?;
                if h.list || path.is_empty() {
                    return Err(alloy_rlp::Error::UnexpectedList.into());
                }
                if path[0] & 0x20 == 0 {
                    let (h, item, whole) = take_item(&mut rest)?;
                    let child = self.child(h, item, whole, s)?;
                    if child == NONE {
                        return Err(Error::WitnessFormat("extension without child"));
                    }
                    Ok(self.push(Node::Extension(path.to_vec(), child), Some(r)))
                } else {
                    let (h, value, _) = take_item(&mut rest)?;
                    if h.list {
                        return Err(alloy_rlp::Error::UnexpectedList.into());
                    }
                    Ok(self.push(Node::Leaf(path.to_vec(), value.to_vec()), Some(r)))
                }
            }
            17 => {
                let mut children = [NONE; 16];
                for slot in children.iter_mut() {
                    let (h, item, whole) = take_item(&mut rest)?;
                    *slot = self.child(h, item, whole, s)?;
                }
                let (h, value, _) = take_item(&mut rest)?;
                if h.list || !value.is_empty() {
                    return Err(Error::WitnessFormat("branch node with value"));
                }
                Ok(self.push(Node::Branch(children), Some(r)))
            }
            _ => Err(alloy_rlp::Error::UnexpectedLength.into()),
        }
    }

    // -- reads ---------------------------------------------------------------

    /// The value stored under `key`, if any.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, Error> {
        self.get_internal(self.root, &to_nibs(key))
    }

    /// The RLP-decoded value stored under `key`, if any.
    pub fn get_rlp<T: alloy_rlp::Decodable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
        match self.get(key)? {
            Some(mut bytes) => Ok(Some(T::decode(&mut bytes)?)),
            None => Ok(None),
        }
    }

    fn get_internal(&self, id: NodeId, key_nibs: &[u8]) -> Result<Option<&[u8]>, Error> {
        match &self.nodes[id as usize] {
            Node::Null => Ok(None),
            Node::Branch(children) => match key_nibs.split_first() {
                Some((i, tail)) => match children[*i as usize] {
                    NONE => Ok(None),
                    child => self.get_internal(child, tail),
                },
                None => Ok(None),
            },
            Node::Leaf(prefix, value) => {
                if strip_prefix_nibs(key_nibs, prefix) == Some(&[][..]) {
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }
            Node::Extension(prefix, child) => match strip_prefix_nibs(key_nibs, prefix) {
                Some(tail) => self.get_internal(*child, tail),
                None => Ok(None),
            },
            Node::Digest(digest) => Err(Error::NodeNotResolved(*digest)),
        }
    }

    /// Whether the trie holds no key.
    pub fn is_empty(&self) -> bool {
        matches!(self.nodes[self.root as usize], Node::Null)
    }

    /// Remove every key.
    pub fn clear(&mut self) {
        self.nodes[self.root as usize] = Node::Null;
        self.refs[self.root as usize] = None;
    }

    // -- hashing -------------------------------------------------------------

    /// The root hash.
    pub fn hash(&mut self) -> B256 {
        match self.nodes[self.root as usize] {
            Node::Null => EMPTY_ROOT,
            _ => match self.reference(self.root) {
                Ref::Digest(d) => d,
                Ref::Bytes(b) => keccak(b).into(),
            },
        }
    }

    fn reference(&mut self, id: NodeId) -> Ref {
        if let Some(r) = &self.refs[id as usize] {
            return r.clone();
        }
        let r = match &self.nodes[id as usize] {
            Node::Null => Ref::Bytes(vec![alloy_rlp::EMPTY_STRING_CODE]),
            Node::Digest(d) => Ref::Digest(*d),
            _ => {
                let encoded = self.encode(id);
                if encoded.len() < 32 {
                    Ref::Bytes(encoded)
                } else {
                    Ref::Digest(keccak(&encoded).into())
                }
            }
        };
        self.refs[id as usize] = Some(r.clone());
        r
    }

    /// The RLP encoding of node `id` (children as references).
    fn encode(&mut self, id: NodeId) -> Vec<u8> {
        match self.nodes[id as usize].clone() {
            Node::Null => vec![alloy_rlp::EMPTY_STRING_CODE],
            Node::Digest(d) => d.to_rlp(),
            Node::Leaf(prefix, value) => {
                let payload = prefix.as_slice().length() + value.as_slice().length();
                let mut out = Vec::with_capacity(payload + 3);
                alloy_rlp::Header { list: true, payload_length: payload }.encode(&mut out);
                prefix.as_slice().encode(&mut out);
                value.as_slice().encode(&mut out);
                out
            }
            Node::Extension(prefix, child) => {
                let child_ref = self.reference(child);
                let payload = prefix.as_slice().length() + child_ref.length();
                let mut out = Vec::with_capacity(payload + 3);
                alloy_rlp::Header { list: true, payload_length: payload }.encode(&mut out);
                prefix.as_slice().encode(&mut out);
                child_ref.encode(&mut out);
                out
            }
            Node::Branch(children) => {
                let mut refs: [Option<Ref>; 16] = Default::default();
                let mut payload = 1; // the empty value
                for (slot, child) in refs.iter_mut().zip(children.iter()) {
                    if *child != NONE {
                        let r = self.reference(*child);
                        payload += r.length();
                        *slot = Some(r);
                    } else {
                        payload += 1;
                    }
                }
                let mut out = Vec::with_capacity(payload + 3);
                alloy_rlp::Header { list: true, payload_length: payload }.encode(&mut out);
                for r in refs.iter() {
                    match r {
                        Some(r) => r.encode(&mut out),
                        None => out.push(alloy_rlp::EMPTY_STRING_CODE),
                    }
                }
                out.push(alloy_rlp::EMPTY_STRING_CODE);
                out
            }
        }
    }

    // -- writes --------------------------------------------------------------

    /// Insert or update `key`; `true` if the trie changed.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> Result<bool, Error> {
        assert!(!value.is_empty(), "value must not be empty");
        self.insert_internal(self.root, &to_nibs(key), value)
    }

    /// Insert or update `key` with the RLP encoding of `value`.
    pub fn insert_rlp(&mut self, key: &[u8], value: impl Encodable) -> Result<bool, Error> {
        self.insert_internal(self.root, &to_nibs(key), value.to_rlp())
    }

    #[inline]
    fn leaf(&mut self, nibs: &[u8], value: Vec<u8>) -> NodeId {
        self.push(Node::Leaf(to_encoded_path(nibs, true), value), None)
    }

    fn insert_internal(&mut self, id: NodeId, key_nibs: &[u8], value: Vec<u8>) -> Result<bool, Error> {
        let changed = match &mut self.nodes[id as usize] {
            Node::Null => {
                self.nodes[id as usize] = Node::Leaf(to_encoded_path(key_nibs, true), value);
                true
            }
            Node::Branch(children) => {
                let Some((i, tail)) = key_nibs.split_first() else {
                    return Err(Error::ValueInBranch);
                };
                let child = children[*i as usize];
                if child != NONE {
                    if !self.insert_internal(child, tail, value)? {
                        return Ok(false);
                    }
                } else {
                    let (i, tail) = (*i as usize, tail.to_vec());
                    let leaf = self.leaf(&tail, value);
                    if let Node::Branch(children) = &mut self.nodes[id as usize] {
                        children[i] = leaf;
                    }
                }
                true
            }
            Node::Leaf(prefix, old_value) => {
                let self_nibs = prefix_nibs(prefix);
                let common_len = lcp(&self_nibs, key_nibs);
                if common_len == self_nibs.len() && common_len == key_nibs.len() {
                    if *old_value == value {
                        return Ok(false);
                    }
                    *old_value = value;
                } else if common_len == self_nibs.len() || common_len == key_nibs.len() {
                    return Err(Error::ValueInBranch);
                } else {
                    let old_value = mem::take(old_value);
                    let split = common_len + 1;
                    let mut children = [NONE; 16];
                    children[self_nibs[common_len] as usize] =
                        self.leaf(&self_nibs[split..], old_value);
                    children[key_nibs[common_len] as usize] = self.leaf(&key_nibs[split..], value);
                    self.replace_with_branch(id, &self_nibs[..common_len], children);
                }
                true
            }
            Node::Extension(prefix, existing_child) => {
                let existing_child = *existing_child;
                let self_nibs = prefix_nibs(prefix);
                let common_len = lcp(&self_nibs, key_nibs);
                if common_len == self_nibs.len() {
                    if !self.insert_internal(existing_child, &key_nibs[common_len..], value)? {
                        return Ok(false);
                    }
                } else if common_len == key_nibs.len() {
                    return Err(Error::ValueInBranch);
                } else {
                    let split = common_len + 1;
                    let mut children = [NONE; 16];
                    children[self_nibs[common_len] as usize] = if split < self_nibs.len() {
                        self.push(
                            Node::Extension(to_encoded_path(&self_nibs[split..], false), existing_child),
                            None,
                        )
                    } else {
                        existing_child
                    };
                    children[key_nibs[common_len] as usize] = self.leaf(&key_nibs[split..], value);
                    self.replace_with_branch(id, &self_nibs[..common_len], children);
                }
                true
            }
            Node::Digest(digest) => return Err(Error::NodeNotResolved(*digest)),
        };
        if changed {
            self.refs[id as usize] = None;
        }
        Ok(changed)
    }

    /// Node `id` becomes `branch`, under an extension for `prefix_nibs` when
    /// that is non-empty.
    fn replace_with_branch(&mut self, id: NodeId, prefix_nibs: &[u8], children: [NodeId; 16]) {
        if prefix_nibs.is_empty() {
            self.nodes[id as usize] = Node::Branch(children);
        } else {
            let branch = self.push(Node::Branch(children), None);
            self.nodes[id as usize] = Node::Extension(to_encoded_path(prefix_nibs, false), branch);
        }
    }

    /// Delete `key`; `true` if it was present.
    pub fn delete(&mut self, key: &[u8]) -> Result<bool, Error> {
        self.delete_internal(self.root, &to_nibs(key))
    }

    fn delete_internal(&mut self, id: NodeId, key_nibs: &[u8]) -> Result<bool, Error> {
        match &self.nodes[id as usize] {
            Node::Null => return Ok(false),
            Node::Branch(children) => {
                let Some((i, tail)) = key_nibs.split_first() else {
                    return Err(Error::ValueInBranch);
                };
                let child = children[*i as usize];
                if child == NONE || !self.delete_internal(child, tail)? {
                    return Ok(false);
                }
                let i = *i as usize;
                if matches!(self.nodes[child as usize], Node::Null) {
                    if let Node::Branch(children) = &mut self.nodes[id as usize] {
                        children[i] = NONE;
                    }
                }
                let Node::Branch(children) = &self.nodes[id as usize] else { unreachable!() };
                let mut remaining = children.iter().enumerate().filter(|(_, c)| **c != NONE);
                // there is always at least one child left
                let (index, orphan) = remaining.next().map(|(i, c)| (i, *c)).unwrap();
                if remaining.next().is_none() {
                    // one child left: the branch collapses into it
                    let new = match mem::replace(&mut self.nodes[orphan as usize], Node::Null) {
                        Node::Leaf(prefix, value) => {
                            let mut nibs = vec![index as u8];
                            nibs.extend(prefix_nibs(&prefix));
                            Node::Leaf(to_encoded_path(&nibs, true), value)
                        }
                        Node::Extension(prefix, child) => {
                            let mut nibs = vec![index as u8];
                            nibs.extend(prefix_nibs(&prefix));
                            Node::Extension(to_encoded_path(&nibs, false), child)
                        }
                        node @ (Node::Branch(_) | Node::Digest(_)) => {
                            // the orphan keeps its slot; the branch becomes an extension to it
                            self.nodes[orphan as usize] = node;
                            Node::Extension(to_encoded_path(&[index as u8], false), orphan)
                        }
                        Node::Null => unreachable!(),
                    };
                    self.nodes[id as usize] = new;
                }
            }
            Node::Leaf(prefix, _) => {
                if strip_prefix_nibs(key_nibs, prefix) != Some(&[][..]) {
                    return Ok(false);
                }
                self.nodes[id as usize] = Node::Null;
            }
            Node::Extension(prefix, child) => {
                let child = *child;
                let mut self_nibs = prefix_nibs(prefix);
                let Some(tail) = strip_prefix_nibs(key_nibs, prefix) else { return Ok(false) };
                if !self.delete_internal(child, tail)? {
                    return Ok(false);
                }
                // an extension points to a branch or digest; re-establish that
                let new = match mem::replace(&mut self.nodes[child as usize], Node::Null) {
                    Node::Null => Some(Node::Null),
                    Node::Leaf(prefix, value) => {
                        self_nibs.extend(prefix_nibs(&prefix));
                        Some(Node::Leaf(to_encoded_path(&self_nibs, true), value))
                    }
                    Node::Extension(prefix, grandchild) => {
                        self_nibs.extend(prefix_nibs(&prefix));
                        Some(Node::Extension(to_encoded_path(&self_nibs, false), grandchild))
                    }
                    node @ (Node::Branch(_) | Node::Digest(_)) => {
                        self.nodes[child as usize] = node;
                        None
                    }
                };
                if let Some(new) = new {
                    self.nodes[id as usize] = new;
                }
            }
            Node::Digest(digest) => return Err(Error::NodeNotResolved(*digest)),
        }
        self.refs[id as usize] = None;
        Ok(true)
    }
}

/// `key_nibs` with a compact-encoded `prefix` stripped off the front, without
/// materialising the prefix's nibbles.
fn strip_prefix_nibs<'a>(key_nibs: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (first, tail) = prefix.split_first()?;
    let mut rest = key_nibs;
    if first & 0x10 != 0 {
        let (k, r) = rest.split_first()?;
        if *k != first & 0xf {
            return None;
        }
        rest = r;
    }
    for byte in tail {
        let (k, r) = rest.split_first_chunk::<2>()?;
        if k[0] != byte >> 4 || k[1] != byte & 0xf {
            return None;
        }
        rest = r;
    }
    Some(rest)
}

// ---------------------------------------------------------------------------
// The guest's state: arena tries + the update logic of `EthereumState`
// ---------------------------------------------------------------------------

/// State and storage tries materialised from a [`WitnessState`].
#[derive(Debug, Clone, Default)]
pub struct ArenaState {
    pub state_trie: ArenaTrie,
    pub storage_tries: HashMap<B256, ArenaTrie>,
}

impl ArenaState {
    /// Build every trie, checking each node against the digest that references
    /// it and each trie against its root; the state root is checked against
    /// `witness.state_root`, the storage roots against the account leaves.
    pub fn from_witness(witness: &WitnessState) -> Result<Self, Error> {
        let state_trie = ArenaTrie::from_stream(witness.state_root, &witness.state_nodes)?;
        let mut storage_tries = HashMap::with_capacity_and_hasher(witness.storage.len(), Default::default());
        for (hashed_address, root, nodes) in &witness.storage {
            let expected = state_trie
                .get_rlp::<TrieAccount>(hashed_address.as_slice())?
                .map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
            if *root != expected {
                return Err(Error::WitnessNodeMismatch(expected));
            }
            storage_tries.insert(*hashed_address, ArenaTrie::from_stream(*root, nodes)?);
        }
        Ok(Self { state_trie, storage_tries })
    }

    /// The account under `hashed_address`, if any.
    pub fn account(&self, hashed_address: &[u8]) -> Result<Option<TrieAccount>, Error> {
        self.state_trie.get_rlp::<TrieAccount>(hashed_address)
    }

    /// The storage slot `hashed_slot` of `hashed_address`, if set.
    pub fn storage(&self, hashed_address: &B256, hashed_slot: &[u8]) -> Result<Option<U256>, Error> {
        let trie = self
            .storage_tries
            .get(hashed_address)
            .expect("A storage trie must be provided for each account");
        trie.get_rlp::<U256>(hashed_slot)
    }

    /// Apply the post-state diff (same semantics as `EthereumState::update`).
    pub fn update(&mut self, post_state: &HashedPostState) {
        for (hashed_address, account) in post_state.accounts.iter() {
            match account {
                Some(account) => {
                    let state_storage = &post_state
                        .storages
                        .get(hashed_address)
                        .cloned()
                        .unwrap_or_else(|| HashedStorage::new(false));
                    let storage_root = self.storage_root_after_update(*hashed_address, state_storage);

                    if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
                        self.state_trie.delete(hashed_address.as_slice()).unwrap();
                        self.storage_tries.remove(hashed_address);
                        continue;
                    }

                    let state_account = TrieAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage_root,
                        code_hash: account.get_bytecode_hash(),
                    };
                    self.state_trie.insert_rlp(hashed_address.as_slice(), state_account).unwrap();
                }
                None => {
                    self.state_trie.delete(hashed_address.as_slice()).unwrap();
                    self.storage_tries.remove(hashed_address);
                }
            }
        }
    }

    fn storage_root_after_update(&mut self, hashed_address: B256, state_storage: &HashedStorage) -> B256 {
        if state_storage.is_empty() {
            if let Some(storage_trie) = self.storage_tries.get_mut(&hashed_address) {
                return storage_trie.hash();
            }
            return self
                .state_trie
                .get_rlp::<TrieAccount>(hashed_address.as_slice())
                .unwrap()
                .map(|account| account.storage_root)
                .unwrap_or(EMPTY_ROOT_HASH);
        }

        let storage_trie = self.storage_tries.entry(hashed_address).or_default();
        if state_storage.wiped {
            storage_trie.clear();
        }
        for (key, value) in state_storage.storage.iter() {
            let key = key.as_slice();
            if value.is_zero() {
                storage_trie.delete(key).unwrap();
            } else {
                storage_trie.insert_rlp(key, *value).unwrap();
            }
        }
        storage_trie.hash()
    }

    /// The state root.
    pub fn state_root(&mut self) -> B256 {
        self.state_trie.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EthereumState;
    use alloy_primitives::{keccak256, U256};
    use reth_trie::Nibbles;

    fn key(i: u64) -> B256 {
        keccak256(i.to_be_bytes())
    }

    fn rng(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn oracle_trie(n: u64, seed: u64) -> MptNode {
        let mut trie = MptNode::default();
        let mut s = seed | 1;
        for i in 0..n {
            trie.insert_rlp(key(i).as_slice(), U256::from(rng(&mut s))).unwrap();
        }
        trie
    }

    fn arena_of(trie: &MptNode) -> ArenaTrie {
        ArenaTrie::from_stream(trie.hash(), &witness_stream(trie)).unwrap()
    }

    #[test]
    fn stream_roundtrip_matches_oracle() {
        for &n in &[0u64, 1, 2, 3, 17, 300, 2000] {
            let oracle = oracle_trie(n, 7 + n);
            let mut arena = arena_of(&oracle);
            assert_eq!(arena.hash(), oracle.hash(), "n={n}");
            for i in 0..n + 50 {
                let k = key(i);
                assert_eq!(
                    arena.get(k.as_slice()).unwrap(),
                    oracle.get(k.as_slice()).unwrap(),
                    "n={n} key {i}"
                );
            }
        }
    }

    #[test]
    fn mutations_match_oracle() {
        let mut oracle = oracle_trie(400, 99);
        let mut arena = arena_of(&oracle);
        let mut s = 12345u64;
        for step in 0..3000u64 {
            let r = rng(&mut s);
            let i = r % 700; // hits existing (0..400) and fresh keys
            let k = key(i);
            match r % 5 {
                0 | 1 => {
                    let v = U256::from(rng(&mut s));
                    let a = arena.insert_rlp(k.as_slice(), v).unwrap();
                    let b = oracle.insert_rlp(k.as_slice(), v).unwrap();
                    assert_eq!(a, b, "insert step {step}");
                }
                2 | 3 => {
                    let a = arena.delete(k.as_slice()).unwrap();
                    let b = oracle.delete(k.as_slice()).unwrap();
                    assert_eq!(a, b, "delete step {step}");
                }
                _ => {
                    assert_eq!(arena.get(k.as_slice()).unwrap(), oracle.get(k.as_slice()).unwrap());
                }
            }
            if step % 97 == 0 {
                assert_eq!(arena.hash(), oracle.hash(), "root after step {step}");
            }
        }
        assert_eq!(arena.hash(), oracle.hash());
        assert_eq!(arena.is_empty(), oracle.is_empty());
    }

    /// Replace the child at `nibble` of the root branch (after descending any
    /// root extension) with an unresolved digest, like a partial witness.
    fn plant_digest(trie: &mut MptNode, nibble: usize) -> bool {
        let mut node = trie;
        loop {
            match node.data_mut() {
                MptNodeData::Extension(_, child) => node = child,
                MptNodeData::Branch(children) => {
                    return match &mut children[nibble] {
                        Some(child) => {
                            let h = child.hash();
                            *child.data_mut() = MptNodeData::Digest(h);
                            true
                        }
                        None => false,
                    }
                }
                _ => return false,
            }
        }
    }

    #[test]
    fn unresolved_subtrees_match_oracle() {
        let mut oracle = oracle_trie(600, 5);
        let full_root = oracle.hash();
        assert!(plant_digest(&mut oracle, 3));
        assert!(plant_digest(&mut oracle, 11));
        assert_eq!(oracle.hash(), full_root, "digest planting keeps the root");
        let mut arena = arena_of(&oracle);
        assert_eq!(arena.hash(), full_root);
        let mut resolved = 0;
        let mut unresolved = 0;
        for i in 0..600u64 {
            let k = key(i);
            match (arena.get(k.as_slice()), oracle.get(k.as_slice())) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a, b);
                    resolved += 1;
                }
                (Err(Error::NodeNotResolved(a)), Err(Error::NodeNotResolved(b))) => {
                    assert_eq!(a, b);
                    unresolved += 1;
                }
                (a, b) => panic!("key {i}: {a:?} vs {b:?}"),
            }
        }
        assert!(resolved > 0 && unresolved > 0, "{resolved} {unresolved}");
        // mutations on resolved paths still agree
        for i in 0..600u64 {
            let k = key(i);
            if arena.get(k.as_slice()).is_ok() {
                let v = U256::from(i * 31 + 7);
                arena.insert_rlp(k.as_slice(), v).unwrap();
                oracle.insert_rlp(k.as_slice(), v).unwrap();
            }
        }
        assert_eq!(arena.hash(), oracle.hash());
    }

    #[test]
    fn tampered_node_is_rejected() {
        let oracle = oracle_trie(50, 3);
        let mut stream = witness_stream(&oracle).to_vec();
        // flip a byte inside the first node's payload
        let last = stream.len() - 1;
        stream[last] ^= 1;
        assert!(matches!(
            ArenaTrie::from_stream(oracle.hash(), &stream),
            Err(Error::WitnessNodeMismatch(_))
        ));
        assert!(ArenaTrie::from_stream(B256::ZERO, &witness_stream(&oracle)).is_err());
    }

    #[test]
    fn state_update_matches_oracle() {
        use reth_primitives_traits::Account;
        let mut s = 777u64;
        let mut eager = EthereumState::default();
        for i in 0..120u64 {
            let addr = key(i);
            let mut storage = MptNode::default();
            for j in 0..(i % 9) {
                storage.insert_rlp(key(1000 + i * 10 + j).as_slice(), U256::from(rng(&mut s))).unwrap();
            }
            let account = TrieAccount {
                nonce: i,
                balance: U256::from(rng(&mut s)),
                storage_root: storage.hash(),
                code_hash: key(5000 + i),
            };
            eager.state_trie.insert_rlp(addr.as_slice(), account).unwrap();
            eager.storage_tries.insert(addr, storage);
        }
        let witness = eager.to_witness_state();
        let mut arena = ArenaState::from_witness(&witness).unwrap();
        assert_eq!(arena.state_root(), eager.state_root());

        let mut post = HashedPostState::default();
        for i in 0..120u64 {
            let addr = key(i);
            match i % 4 {
                0 => {
                    post.accounts.insert(addr, None);
                }
                1 => {
                    post.accounts.insert(
                        addr,
                        Some(Account { nonce: i + 1, balance: U256::from(rng(&mut s)), bytecode_hash: Some(key(5000 + i)) }),
                    );
                    let mut hs = HashedStorage::new(false);
                    for j in 0..6u64 {
                        let v = if j % 2 == 0 { U256::ZERO } else { U256::from(rng(&mut s)) };
                        hs.storage.insert(key(1000 + i * 10 + j), v);
                    }
                    post.storages.insert(addr, hs);
                }
                2 => {
                    post.accounts.insert(
                        addr,
                        Some(Account { nonce: 0, balance: U256::ZERO, bytecode_hash: None }),
                    );
                    post.storages.insert(addr, HashedStorage::new(true));
                }
                _ => {
                    post.accounts.insert(
                        key(9000 + i),
                        Some(Account { nonce: 1, balance: U256::from(5), bytecode_hash: None }),
                    );
                }
            }
        }
        eager.update(&post);
        arena.update(&post);
        assert_eq!(arena.state_root(), eager.state_root());
        let _ = Nibbles::default();
    }
}
