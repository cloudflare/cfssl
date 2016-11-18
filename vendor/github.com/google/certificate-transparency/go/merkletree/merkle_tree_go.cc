#include "merkletree/merkle_tree.h"

#include <assert.h>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "merkle_tree_go.h"

extern "C" {
// Some hollow functions to cast the void* types into what they really
// are, they're only really here to provide a little bit of type
// safety.  Hopefully these should all be optimized away into oblivion
// by the compiler.
static inline MerkleTree* MT(TREE tree) {
  assert(tree);
  return static_cast<MerkleTree*>(tree);
}
static inline Sha256Hasher* H(HASHER hasher) {
  assert(hasher);
  return static_cast<Sha256Hasher*>(hasher);
}

HASHER NewSha256Hasher() {
  return new Sha256Hasher;
}

TREE NewMerkleTree(HASHER hasher) {
  return new MerkleTree(std::unique_ptr<SerialHasher>(H(hasher)));
}

void DeleteMerkleTree(TREE tree) {
  delete MT(tree);
}

size_t NodeSize(TREE tree) {
  return MT(tree)->NodeSize();
}

size_t LeafCount(TREE tree) {
  return MT(tree)->LeafCount();
}

size_t LeafHash(TREE tree, size_t leaf, void* buf, size_t buf_len) {
  const MerkleTree* t(MT(tree));
  const size_t nodesize(t->NodeSize());
  if (buf == NULL || buf_len < nodesize) {
    return 0;
  }
  const std::string& hash = t->LeafHash(leaf);
  assert(nodesize == hash.size());
  memcpy(buf, hash.data(), nodesize);
  return nodesize;
}

size_t LevelCount(TREE tree) {
  const MerkleTree* t(MT(tree));
  return t->LevelCount();
}

size_t AddLeaf(TREE tree, void* leaf, size_t leaf_len) {
  MerkleTree* t(MT(tree));
  return t->AddLeaf(std::string(static_cast<char*>(leaf), leaf_len));
}

size_t AddLeafHash(TREE tree, void* hash, size_t hash_len) {
  MerkleTree* t(MT(tree));
  return t->AddLeafHash(
      std::string(static_cast<char*>(hash), hash_len));
}

size_t CurrentRoot(TREE tree, void* buf, size_t buf_len) {
  MerkleTree* t(MT(tree));
  const size_t nodesize(t->NodeSize());
  if (buf == NULL || buf_len < nodesize) {
    return 0;
  }
  const std::string& hash = t->CurrentRoot();
  assert(nodesize == hash.size());
  memcpy(buf, hash.data(), nodesize);
  return nodesize;
}

size_t RootAtSnapshot(TREE tree, size_t snapshot, void* buf, size_t buf_len) {
  MerkleTree* t(MT(tree));
  const size_t nodesize(t->NodeSize());
  if (buf == nullptr || buf_len < nodesize) {
    return 0;
  }
  const std::string& hash = t->RootAtSnapshot(snapshot);
  assert(nodesize == hash.size());
  memcpy(buf, hash.data(), nodesize);
  return nodesize;
}

// Copies the fixed-length entries from |path| into the GoSlice
// pointed to by |dst|, one after the other in the same order.
// |num_copied| is set to the number of entries copied.
bool CopyNodesToSlice(const std::vector<std::string>& path, void* dst,
                      size_t dst_len, size_t nodesize, size_t* num_copied) {
  assert(dst);
  assert(num_copied);
  if (dst_len < path.size() * nodesize) {
    *num_copied = 0;
    return false;
  }
  char *e(static_cast<char*>(dst));
  for (int i = 0; i < path.size(); ++i) {
    assert(nodesize == path[i].size());
    memcpy(e, path[i].data(), nodesize);
    e += nodesize;
  }
  *num_copied = path.size();
  return true;
}

bool PathToCurrentRoot(TREE tree, size_t leaf, void* out, size_t out_len, size_t* num_entries) {
  MerkleTree* t(MT(tree));
  const std::vector<std::string> path = t->PathToCurrentRoot(leaf);
  return CopyNodesToSlice(path, out, out_len, t->NodeSize(), num_entries);
}

bool PathToRootAtSnapshot(TREE tree, size_t leaf, size_t snapshot, void *out,
                            size_t out_len, size_t *num_entries) {
  MerkleTree* t(MT(tree));
  const std::vector<std::string> path =
      t->PathToRootAtSnapshot(leaf, snapshot);
  return CopyNodesToSlice(path, out, out_len, t->NodeSize(), num_entries);
}

bool SnapshotConsistency(TREE tree, size_t snapshot1, size_t snapshot2,
                           void* out, size_t out_len, size_t* num_entries) {
  MerkleTree* t(MT(tree));
  const std::vector<std::string> path =
      t->SnapshotConsistency(snapshot1, snapshot2);
  return CopyNodesToSlice(path, out, out_len, t->NodeSize(), num_entries);
}

}  // extern "C"
