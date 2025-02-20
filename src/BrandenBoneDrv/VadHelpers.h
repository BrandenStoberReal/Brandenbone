#pragma once

#define SANITIZE_PARENT_NODE(Parent) ((PRTL_BALANCED_NODE)(((ULONG_PTR)(Parent)) & ~0x3))

//
// Various Rtl macros that reference Parent use private versions here since
// Parent is overloaded with Balance.
//

//
//  The macro function Parent takes as input a pointer to a splay link in a
//  tree and returns a pointer to the splay link of the parent of the input
//  node.  If the input node is the root of the tree the return value is
//  equal to the input value.
//
//  PRTL_SPLAY_LINKS
//  MiParent (
//      PRTL_SPLAY_LINKS Links
//      );
//

#define MiParent(Links) (               \
    (PRTL_SPLAY_LINKS)(SANITIZE_PARENT_NODE((Links)->ParentValue)) \
    )

//
//  The macro function IsLeft takes as input a pointer to a splay link
//  in a tree and returns TRUE if the input node is the left child of its
//  parent, otherwise it returns FALSE.
//
//  BOOLEAN
//  MiIsLeft (
//      PRTL_SPLAY_LINKS Links
//      );
//

#define MiIsLeft(Links) (                                   \
    (RtlLeftChild(MiParent(Links)) == (PRTL_SPLAY_LINKS)(Links)) \
    )

//
//  The macro function IsRight takes as input a pointer to a splay link
//  in a tree and returns TRUE if the input node is the right child of its
//  parent, otherwise it returns FALSE.
//
//  BOOLEAN
//  MiIsRight (
//      PRTL_SPLAY_LINKS Links
//      );
//

#define MiIsRight(Links) (                                   \
    (RtlRightChild(MiParent(Links)) == (PRTL_SPLAY_LINKS)(Links)) \
    )

#define MI_MAKE_PARENT(ParentNode, ExistingBalance) \
    (PRTL_BALANCED_NODE)((ULONG_PTR)(ParentNode) | (((ULONG_PTR)ExistingBalance) & 0x3))

#define COUNT_BALANCE_MAX(a)

TABLE_SEARCH_RESULT MiFindNodeOrParent(IN PMM_AVL_TABLE Table, IN ULONG_PTR StartingVpn, OUT PRTL_BALANCED_NODE* NodeOrParent);
VOID MiPromoteNode(IN PRTL_BALANCED_NODE C);
ULONG MiRebalanceNode(IN PRTL_BALANCED_NODE S);
VOID MiRemoveNode(IN PRTL_BALANCED_NODE NodeToDelete, IN PMM_AVL_TABLE Table);