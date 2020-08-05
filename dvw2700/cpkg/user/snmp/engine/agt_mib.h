/* ====================================================================
 * Copyright (c) 1997-1999
 *                      SMASH, Harrie Hazewinkel.  All rights reserved.
 *
 * This product is developed by Harrie Hazewinkel and updates the
 * original SMUT compiler made as his graduation project at the
 * University of Twente.
 *
 * SMASH is a software package containing an SNMP MIB compiler and
 * an SNMP agent system. The package can be used for development
 * of monolithic SNMP agents and contains a compiler which compiles
 * MIB definitions into C-code to developed an SNMP agent.
 * More information about him and this software product can
 * be found on http://operations.ceo.org/~harrie/smash/.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Harrie Hazewinkel"
 *
 * 4. The name of the Copyright holder must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Harrie Hazewinkel"
 *    Also acknowledged are:
 *    - The Simple group of the University of Twente,
 *          http://wwwsnmp.cs.utwente.nl/
 *    - The MUSIQ workpackage of the DESIRE project,
 *          http://www-musiq.jrc.it/
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR, ITS DISTRIBUTORS
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================*/

#ifndef _AGT_MIB_H_
#define _AGT_MIB_H_

#include "asn1.h"

extern oid	null_oid[];
extern long	long_return;
extern unsigned char	return_buf[];

#define MAX_OCTSTR_LEN	256

/* MIB search types */
#define EXACT	0
#define NEXT	1
#define INDEX	2

#define READ	1
#define WRITE	0

/* MIB parse phases */
#define RESERVE1	0
#define CHECK	0
#define RESERVE2	1
#define COMMIT		2
#define ACTION		3
#define FREE		4

/* MIB access control list for variable and sort of variable	*/
#define SCALAR		1	/* Variable is scalar		*/
#define COLUMN		2	/* variable is column in table	*/
#define SORT		3	/* Variable is scalar or column n table */
#define RONLY		4	/* variable has only read access	*/
#define RWRITE		8	/* variable has write access	*/
#define NOACCESS	16	/* variable is not accessible	*/
#define ACCESS		28	/* Variable its access		*/
#define	OLDSTUB		32	/* Variable is implemented with old stub api */

#define MAX_OID_LEN	32
typedef struct {
   int		namelen;
   oid		name[ MAX_OID_LEN ];
} Oid;

#define	MAX_SUFFIX_LEN	5
typedef struct {
    int		namelen;
    oid		name[ MAX_SUFFIX_LEN ];
} Oid_suffix;

typedef struct {
    char	syntax;		/* syntaxtype of object */
    char	acl_sort;	/* access control list and sort of object */
    unsigned char	*(*findVar)();  /* function that finds value of the object */
    Oid_suffix	oidSuffix;	/* suffix oid part of object */
} Object;

#define MAX_PREFIX_LEN	16
typedef struct {
    int		namelen;
    oid		name[ MAX_PREFIX_LEN ];
} Oid_prefix;

struct subtree_t {
    struct subtree_t *next;	/* Next sub tree */
    Object	*variables;	/* pointer to variables array */
				/* The following are similar to the type of Oid */
				/* but this is only internal and safes spaces. */
    int		prefix_length;	/* length of objid */
    oid         *prefix;	/* value of objid */
};

typedef struct subtree_t SubTree;

/* Only defined for use in BACKWARDS mode
   Should not be used otherwise!! */
struct variable {
    unsigned char          magic;          /* passed to function as a hint */
    char            type;           /* type of variable */
/* See important comment in snmp_vars.c relating to acl */
    unsigned short         acl;            /* access control list for variable */
    unsigned char          *(*findVar)();  /* function that finds variable */
    unsigned char          namelen;        /* length of above */
    oid             name[32];       /* object identifier of variable */
};

unsigned char  *getStatPtr();
int insert_group_in_mib(SubTree *tree);
int	compare(Oid *var1,Oid *var2);
int	compare_tree(Oid *var1, Oid *var2);
void	print_objid(char *str, Oid *var);

#define INSERT_IN_MIB(vars, objectId) \
	{ \
	static SubTree value =  { NULL, vars, (sizeof(objectId)/sizeof(oid)), objectId}; \
	insert_group_in_mib(&value); \
	} \

#ifndef TRUE
#define TRUE	1
#endif
#ifndef FALSE
#define	FALSE	0
#endif

/* The root oid required for the MIB */
#define O_ctitt	0
#define	O_iso	1

#define MIB_GEN_ERROR	(unsigned char*)-1
#define NO_MIBINSTANCE	NULL

#define Access_rec void

#endif	//_AGT_MIB_H_
