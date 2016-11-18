#include <stdbool.h>
#include <sys/types.h>

#ifndef GO_MERKLETREE_MERKLE_TREE_H_
#define GO_MERKLETREE_MERKLE_TREE_H_

// These types & functions provide a trampoline to call the C++ MerkleTree
// implementation from within Go code.
//
// Generally we try to jump through hoops to not allocate memory from the C++
// side, but rather have Go allocate it inside its GC memory such that we don't
// have to worry about leaks.  Apart from the obvious benefit of doing it this
// way, it usually also means one less memcpy() too which is nice.

#ifdef __cplusplus
extern "C" {
#endif

// The _cgo_export.h file doesn't appear to exist when this header is pulled in
// to the .go file, because of this we can't use types like GoSlice here and so
// we end up with void* everywhere;  we'll at least typedef them so that the
// source is a _little_ more readable.
// Grumble grumble.
typedef void* HASHER;
typedef void* TREE;

// Allocators & deallocators:

// Creates a new Sha256Hasher
HASHER NewSha256Hasher();

// Creates a new MerkleTree passing in |hasher|.
// The MerkleTree takes ownership of |hasher|.
TREE NewMerkleTree(HASHER hasher);

// Deletes the passed in |tree|.
void DeleteMerkleTree(TREE tree);

// MerkleTree methods below.
// See the comments in ../../merkletree/merkle_tree.h for details

size_t NodeSize(TREE tree);
size_t LeafCount(TREE tree);
size_t LeafHash(TREE tree, size_t leaf, void* buf, size_t buf_len);
size_t LevelCount(TREE tree);
size_t AddLeaf(TREE tree, void* leaf, size_t leaf_len);
size_t AddLeafHash(TREE tree, void* hash, size_t hash_len);
size_t CurrentRoot(TREE tree, void *buf, size_t buf_len);
size_t RootAtSnapshot(TREE tree, size_t snapshot, void* buf, size_t buf_len);

// |out| must contain sufficent space to hold all of the path elements
// sequentially.
// |num_entries| is set to the number of actual elements stored in |out|.
bool PathToCurrentRoot(TREE tree, size_t leaf, void* out, size_t out_len,
                       size_t* num_entries);

// |out| must contain sufficent space to hold all of the path elements
// sequentially.
// |num_entries| is set to the number of actual elements stored in |out|.
bool PathToRootAtSnapshot(TREE tree, size_t leaf, size_t snapshot, void* out,
                            size_t out_len, size_t* num_entries);

// |out| must contain sufficent space to hold all of the path elements
// sequentially.
// |num_entries| is set to the number of actual elements stored in |out|.
bool SnapshotConsistency(TREE tree, size_t snapshot1, size_t snapshot2,
                           void* out, size_t out_len, size_t* num_entries);

#ifdef __cplusplus
}
#endif

#endif  // GO_MERKLETREE_MERKLE_TREE_H_
