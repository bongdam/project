#ifndef __PARAMETER_API_C__
#define __PARAMETER_API_C__

#include "parameter_api.h"
#include "prmt_igd.h"
#include <ctype.h>

#ifdef __DAVO__
#include <sys/types.h>
#include <signal.h>
#include <bcmnvram.h>
#include <stdarg.h>
#include <libytool.h>
#include <strtok_s.h>

extern int nvram_commit(void);
#endif

struct sCWMP_ENTITY *pPrmtTableRoot = NULL;
struct objectNum *pObjectNum = NULL;
struct node *pUpdatePrmtList = NULL;
/*******************************************************************/
/*  Data Type Duplicate Utility APIs */
/*******************************************************************/
int *intdup(int value)
{
	int *num = malloc(sizeof(int));
	if (num)
		*num = value;
	return num;
}

unsigned int *uintdup(unsigned int value)
{
	unsigned int *num = malloc(sizeof(unsigned int));
	if (num)
		*num = value;
	return num;
}

int *booldup(int value)
{
	return intdup(value);
}

time_t *timedup(time_t value)
{
	time_t *num = malloc(sizeof(time_t));
	if (num)
		*num = value;
	return num;
}

/*******************************************************************/
/*  Utility APIs */
/*******************************************************************/
int add_objectNum(char *name, unsigned int i)
{
	struct objectNum *n;

	if ((name == NULL) || (STRLEN(name) == 0))
		return -1;

	n = malloc(sizeof(struct objectNum));
	if (n == NULL)
		return -1;

	n->name = strdup(name);
	if (n->name == NULL) {
		free(n);
		return -1;
	}

	n->num = i;
	n->next = pObjectNum;
	pObjectNum = n;
	return 0;
}

int get_objectNextNum(char *name, unsigned int *i)
{
	struct objectNum *n = pObjectNum;

	if ((name == NULL) || (STRLEN(name) == 0) || (i == NULL))
		return -1;
	*i = 1;
	while (n != NULL) {
		if (nv_strcmp(name, n->name) == 0) {
			n->num++;
			*i = n->num;
			break;
		}
		n = n->next;
	}

	if (n == NULL)		//not found
		add_objectNum(name, *i);

	return 0;
}

/***********************************************************************/
/* Node utility functions. */
/***********************************************************************/
int push_node_data(struct node **root, void *data)
{
	struct node *new_node;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((root == NULL) || (data == NULL))
		return -1;

	new_node = malloc(sizeof(struct node));
	if (new_node == NULL)
		return -1;

	new_node->next = NULL;
	new_node->data = data;

	while (*root)
		root = &(*root)->next;
	*root = new_node;

	return 0;
}

void *pop_node_data(struct node **root)
{
	struct node *c;
	void *data;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((root == NULL) || (*root == NULL))
		return NULL;

	//remove from first one
	c = *root;
	*root = c->next;
	data = c->data;
	free(c);

	return data;
}

void *get_node_data(struct node *root, int index)
{
	struct node *c;
	void *data = NULL;
	int i = 0;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((root == NULL) || index < 0)
		return NULL;

	c = root;
	while (c != NULL) {
		if (i == index) {
			data = c->data;
			break;
		}
		i++;
		c = c->next;
	}

	return data;
}

void *remove_node(struct node **root, int index)
{
	struct node *c, **pre;
	void *data = NULL;
	int i = 0;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((root == NULL) || index < 0)
		return NULL;

	c = *root;
	pre = root;
	while (c != NULL) {
		if (i == index) {
			data = c->data;
			*pre = c->next;
			free(c);
			break;
		}
		i++;
		pre = &c->next;
		c = c->next;
	}
	return data;
}

int get_node_count(struct node *node)
{
	struct node *c = node;
	int ret = 0;
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	while (c != NULL) {
		ret++;
		c = c->next;
	}
	return ret;
}

/*******************************************************************/
/*  Internal APIs */
/*******************************************************************/
int ParameterEntityCount(struct sCWMP_ENTITY table[])
{
	struct sCWMP_ENTITY *t;
	int i = 0;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (table) {
		if (table[0].flag & CWMP_LNKLIST) {	// linked list
			for (t = table; t->sibling; t = t->sibling)
				i++;
		} else {	// array
			for (t = table; t->name[0]; t++)
				i++;
		}
		i += 1;
	}
	CWMPDBG(3, (stderr, "<%s:%d>count=%d\n", __FUNCTION__, __LINE__, i));
	return i;
}

int getPathAndObjNum(char *name, char **new_name, int *num)
{
	char *p;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (name == NULL || new_name == NULL || num == NULL)
		return -1;

	*new_name = strdup(name);
	if (*new_name == NULL)
		return -1;

	*num = 0;
	p = *new_name + STRLEN(*new_name) - 1;
//      fprintf( stderr, "%c\n", *p );
	if (*p == '.') {
		*p = '\0';
		p--;
		while (isdigit(*p) && (p != *new_name))
			p--;
		if (*p == '.') {
			*p = '\0';
			p++;
			*num = atoi(p);
			CWMPDBG(2, (stderr, "<%s:%d>name:%s, num:%d\n", __FUNCTION__, __LINE__, *new_name, *num));
			return 0;
		}
	}
	free(*new_name);
	*new_name = NULL;
	return -1;
}

#define PARAMETER_MAX_LEVEL 16
int Entity_Level = -1;
struct sCWMP_ENTITY *Entity_Pointer[PARAMETER_MAX_LEVEL];
char *Entity_NamePrefix[PARAMETER_MAX_LEVEL];
void set_DefaultEntityPointer(void)
{
	int i;
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (Entity_Level > -1)
		for (i = 0; i <= Entity_Level; i++)
			free(Entity_NamePrefix[i]);
	Entity_Level = -1;
	memset(Entity_Pointer, 0, sizeof(Entity_Pointer));
	memset(Entity_NamePrefix, 0, sizeof(Entity_NamePrefix));
	return;
}

int get_NextParameterName(char **name, int next_level)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((name == NULL) && (Entity_Level == -1))
		return -1;
	*name = NULL;

	while (1) {
		if ((Entity_Pointer[Entity_Level] == NULL)
		    || (nv_strcmp(Entity_Pointer[Entity_Level]->name, "") == 0)) {
			//one level back
			free(Entity_NamePrefix[Entity_Level]);
			Entity_NamePrefix[Entity_Level] = NULL;
			Entity_Level--;
			if (Entity_Level == -1)
				return -1;	//finish
			continue;
		}
		{
			struct sCWMP_ENTITY *pre_entity;
			int bufsize;
			bufsize = STRLEN(Entity_NamePrefix[Entity_Level]) + STRLEN(Entity_Pointer[Entity_Level]->name) + 2;
			*name = malloc(sizeof(char) * bufsize);
			if (*name) {
				if (Entity_Pointer[Entity_Level]->type == eCWMP_tOBJECT)
					snprintf(*name, bufsize, "%s%s.", Entity_NamePrefix[Entity_Level],
						 Entity_Pointer[Entity_Level]->name);
				else
					snprintf(*name, bufsize, "%s%s", Entity_NamePrefix[Entity_Level],
						 Entity_Pointer[Entity_Level]->name);
			}
//              fprintf(stderr, "<%s:%d> name-> %s\n", __FUNCTION__, __LINE__, *name);
			//move to next entry
			pre_entity = Entity_Pointer[Entity_Level];
			if (Entity_Pointer[Entity_Level]->flag & CWMP_LNKLIST)
				Entity_Pointer[Entity_Level] = Entity_Pointer[Entity_Level]->sibling;
			else
				Entity_Pointer[Entity_Level] = &Entity_Pointer[Entity_Level][1];

			if ((pre_entity->next_table != NULL) && (next_level == 0)) {
				if (Entity_Level + 1 >= PARAMETER_MAX_LEVEL) {
					CWMPDBG(0,
						(stderr, "<%s:%d>The ParameterName's depth is too long.\n", __FUNCTION__,
						 __LINE__));
					break;
				}
				//one level forward
				Entity_Level++;
				Entity_Pointer[Entity_Level] = pre_entity->next_table;
				Entity_NamePrefix[Entity_Level] = strdup(*name);
			}
//              fprintf(stderr, "<%s:%d> name-> %s\n", __FUNCTION__, __LINE__, *name);
			break;
		}
	}

	return 0;
}

/*******************************************************************/
/*  Table & Object APIs */
/*******************************************************************/
int init_ParameterTable(struct sCWMP_ENTITY **root, struct sCWMP_ENTITY table[], char *prefix)
{
	int table_count, i;
	char new_prefix[MAX_PRMT_NAME_LEN];

	CWMPDBG(3, (stderr, "<%s:%d>prefix=%s(table first name:%s)\n", __FUNCTION__, __LINE__, prefix, table[0].name));
	table_count = ParameterEntityCount(table);
//      fprintf( stderr, "%s:%s table size:%d\n", __FUNCTION__, prefix, table_count );
	*root = malloc(table_count * sizeof(struct sCWMP_ENTITY));
	if (*root == NULL)
		return -1;
	memcpy(*root, table, table_count * sizeof(struct sCWMP_ENTITY));

//      fprintf( stderr, "%d\n", __LINE__ );
	for (i = 0; i < table_count; i++) {
		//some objects cant be written but can be updated.
		if ((table[i].type == eCWMP_tOBJECT) && (table[i].setvalue != NULL)) {
			int count, j;
			struct sCWMP_ENTITY *ctable, *ntable;
			if ((prefix == NULL) || (prefix[0] == 0))
				snprintf(new_prefix, MAX_PRMT_NAME_LEN, "%s.", table[i].name);
			else
				snprintf(new_prefix, MAX_PRMT_NAME_LEN, "%s%s.", prefix, table[i].name);
//                      fprintf( stderr, "A writable Object, call createobject func.\n" );
			if (table[i].setvalue) {
				table[i].setvalue(new_prefix, &(*root)[i], eCWMP_tINITOBJ, &(*root)[i].next_table);
				//this object may update in the future.
				push_node_data(&pUpdatePrmtList, strdup(new_prefix));
			}
			count = ParameterEntityCount((*root)[i].next_table);
//                      fprintf( stderr, "%s table size:%d\n", new_prefix, count );
			ctable = (*root)[i].next_table;
			for (j = 0; j < count && j < 128; j++) {
				if (ctable->next_table) {
					char tmp_prefix[MAX_PRMT_NAME_LEN];
					ntable = ctable->next_table;	//backup pointer
					snprintf(tmp_prefix, MAX_PRMT_NAME_LEN, "%s%s.", new_prefix, ctable->name);
					if (init_ParameterTable(&ctable->next_table, ntable, tmp_prefix) < 0)
						return -1;
				}
				ctable = ctable->sibling;
			}
		}

		if (table[i].next_table) {
			if ((prefix[0] == 0) || (prefix == NULL))
				snprintf(new_prefix, MAX_PRMT_NAME_LEN, "%s.", table[i].name);
			else
				snprintf(new_prefix, MAX_PRMT_NAME_LEN, "%s%s.", prefix, table[i].name);
			if (init_ParameterTable(&(*root)[i].next_table, table[i].next_table, new_prefix) < 0)
				return -1;
		}
	}

	return 0;
}

int destroy_ParameterTable(struct sCWMP_ENTITY *table)
{
	struct sCWMP_ENTITY *c, *next;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (table == NULL)
		return -1;

	c = table;
	if (c->flag & CWMP_LNKLIST) {
		while (c) {
//                      fprintf( stderr, "<%s>lnklist:%s\n", __FUNCTION__, c->name );
			if (c->next_table)
				destroy_ParameterTable(c->next_table);
			if (c->accesslist)	//free accesslist string
				free(c->accesslist);
			next = c->sibling;
			free(c);
			c = next;
		}
	} else {
		int i, num;
		num = ParameterEntityCount(c);
		for (i = 0; i < num; i++) {
//                      fprintf( stderr, "<%s>%s\n", __FUNCTION__, c[i].name );
			if (c[i].next_table)
				destroy_ParameterTable(c[i].next_table);
			if (c[i].accesslist)	//free accesslist string
				free(c[i].accesslist);
		}
		free(c);
	}
	return 0;
}

int create_Object(struct sCWMP_ENTITY **table, struct sCWMP_ENTITY ori_table[], int size, int num, int from)
{
	int i;
	struct sCWMP_ENTITY *n;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((table == NULL) || (ori_table == NULL) || (size <= 0) || (from <= 0))
		return -1;

	while (*table)
		table = &(*table)->sibling;

	for (i = 0; i < num; i++) {
		n = malloc(size);
		if (n == NULL)
			return -1;
		memcpy(n, ori_table, size);
		snprintf(n->name, sizeof(n->name), "%d", i + from);
		*table = n;
		table = &n->sibling;
	}
	return 0;
}

int add_Object(char *name, struct sCWMP_ENTITY **table, struct sCWMP_ENTITY ori_table[], int size, unsigned int *num)
{
	struct sCWMP_ENTITY **last_sibling;
	struct sCWMP_ENTITY *ctable, *ntable;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((name == NULL) || (table == NULL) || (ori_table == NULL) || (size <= 0) || (num == NULL))
		return -1;

	if (*num == 0)
		if (get_objectNextNum(name, num) < 0)
			return -1;

	last_sibling = table;
	while (*last_sibling)
		last_sibling = &(*last_sibling)->sibling;
	create_Object(last_sibling, ori_table, size, 1, *num);

	ctable = *last_sibling;
	if ((ctable != NULL) && (ctable->next_table != NULL)) {
		char tmp_prefix[MAX_PRMT_NAME_LEN];

		ntable = ctable->next_table;
		//snprintf( tmp_prefix, MAX_PRMT_NAME_LEN, "%s.%s.", name, ctable->name );
		snprintf(tmp_prefix, MAX_PRMT_NAME_LEN, "%s%s.", name, ctable->name);
		if (init_ParameterTable(&ctable->next_table, ntable, tmp_prefix) < 0)
			return -1;
	}

	return 0;
}

int del_Object(char *name, struct sCWMP_ENTITY **table, int num)
{
	struct sCWMP_ENTITY **ctable, *match;
	char buf[MAX_PRMT_NAME_LEN];

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((table == NULL) || (num <= 0))
		return -1;

	snprintf(buf, sizeof(buf), "%d", num);
	ctable = table;
	while (*ctable) {
		if (nv_strcmp((*ctable)->name, buf) == 0)
			break;
		ctable = &(*ctable)->sibling;
	}
	if (*ctable == NULL)
		return ERR_9005;	//doesn't match the number

	match = *ctable;
	*ctable = (*ctable)->sibling;

	if (match->next_table)
		destroy_ParameterTable(match->next_table);
	if (match->accesslist)
		free(match->accesslist);
	free(match);
	return 0;
}

int add_SiblingEntity(struct sCWMP_ENTITY **table, struct sCWMP_ENTITY *new_entity)
{
	struct sCWMP_ENTITY **c;

	if (table == NULL || new_entity == NULL)
		return -1;
	if ((new_entity->flag & CWMP_LNKLIST) == 0)
		return -1;

	c = table;
	while (*c)
		c = &(*c)->sibling;
	*c = new_entity;
	new_entity->sibling = NULL;
	return 0;
}

struct sCWMP_ENTITY *remove_SiblingEntity(struct sCWMP_ENTITY **table, unsigned int num)
{
	struct sCWMP_ENTITY **ctable, *match = NULL;
	char buf[MAX_PRMT_NAME_LEN];

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((table == NULL) || (num <= 0))
		return match;

	snprintf(buf, sizeof(buf), "%d", num);
	ctable = table;
	while (*ctable) {
		if (nv_strcmp((*ctable)->name, buf) == 0)
			break;
		ctable = &(*ctable)->sibling;
	}
	if (*ctable == NULL)
		return match;	//doesn't match the number

	match = *ctable;
	*ctable = (*ctable)->sibling;
	match->sibling = NULL;	/*reset the sibling pointer */

	return match;
}

/*******************************************************************/
/*  Global APIs */
/*******************************************************************/
int init_Parameter(void)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	return init_ParameterTable(&pPrmtTableRoot, tROOT, "");
}

int free_Parameter(void)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	destroy_ParameterTable(pPrmtTableRoot);
	pPrmtTableRoot = NULL;
	return 0;
}

int update_Parameter(void)
{
	int num, i;
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));

	num = get_node_count(pUpdatePrmtList);
	i = 0;
	while (i < num) {
		char *name = NULL;
		struct sCWMP_ENTITY *pEntity;

		name = (char *)get_node_data(pUpdatePrmtList, i);
		if (name == NULL)
			continue;

		if (get_ParameterEntity(name, &pEntity) < 0) {
			//if not exist, remove it
			name = remove_node(&pUpdatePrmtList, i);
			if (name)
				free(name);
		} else {
			if (pEntity->setvalue) {
				pEntity->setvalue(name, pEntity, eCWMP_tUPDATEOBJ, NULL);
			}
			i++;
		}
	}

	return 0;
}

int get_ParameterEntity(char *name, struct sCWMP_ENTITY **entity)
{
	struct sCWMP_ENTITY *t = pPrmtTableRoot;
	char str[(name) ? (STRLEN(name) + 1): 1];
	char *p, *q = NULL;

	CWMPDBG(3, (stderr, "<%s:%d> name->%s\n", __FUNCTION__, __LINE__, name));
	if (name == NULL || entity == NULL || t == NULL)
		return -1;
	*entity = NULL;
	snprintf(str, sizeof(str), "%s", name);
	for (p = STRTOK_R(str, ".\n\r", &q); p && t; t = t->next_table) {
		if (t[0].flag & CWMP_LNKLIST) {
			while (t && nv_strcmp(t->name, p))
				t = t->sibling;
		} else {
			while (t->name[0] && nv_strcmp(t->name, p))
				t++;
		}
		if (t == NULL || t->name[0] == '\0')
			break;
		p = STRTOK_R(NULL, ".\n\r", &q);
		if (p == NULL)
			*entity = t;
	}

	return (*entity) ? 0 : ERR_9005;
}

int get_ParameterName(char *prefix, int next_level, char **name)
{
	struct sCWMP_ENTITY *entity = NULL;
	int IsEndWithDot = 0;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (name == NULL)
		return -1;

//      fprintf(stderr, "<%s:%d> prefix-> %s\n", __FUNCTION__, __LINE__, prefix);
	*name = NULL;
	if (prefix) {
		//Entity_Level = -1;
		set_DefaultEntityPointer();
		if (STRLEN(prefix) == 0)	//special case
		{
			Entity_Level = 0;
			Entity_Pointer[Entity_Level] = pPrmtTableRoot;
			Entity_NamePrefix[Entity_Level] = strdup(prefix);
			return get_NextParameterName(name, next_level);
		}

		if (get_ParameterEntity(prefix, &entity) < 0)
			return ERR_9005;

		IsEndWithDot = (prefix[STRLEN(prefix) - 1] == '.');
		if (((entity->type & eCWMP_tOBJECT) == eCWMP_tOBJECT) && (IsEndWithDot == 1)) {
			Entity_Level = 0;
			Entity_Pointer[Entity_Level] = entity->next_table;
			Entity_NamePrefix[Entity_Level] = strdup(prefix);
			if (next_level == 0)	//wt-121v8 2.26
			{
				*name = strdup(prefix);
				return 0;
			} else
				return get_NextParameterName(name, next_level);
		} else if (((entity->type & eCWMP_tOBJECT) != eCWMP_tOBJECT) && (IsEndWithDot == 0))	//no next level && not end with '.'
		{
			if (next_level == 0) {
				*name = strdup(prefix);
				return 0;
			} else
				return -1;	//next_level==0 should be a partial path
		} else {	//error
			return -1;
		}
	} else if (Entity_Level >= 0) {
		return get_NextParameterName(name, next_level);
	}

	return -1;
}

int get_ParameterNameCount(char *prefix, int next_level)
{
	char *name = NULL;
	int err = 0;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (prefix == NULL || STRLEN(prefix) == 0)
		err = get_ParameterName("", next_level, &name);
	else
		err = get_ParameterName(prefix, next_level, &name);

	if ((err < 0) & (next_level == 1))	//object but no instances, return 0, not error code
	{
		struct sCWMP_ENTITY *entity = NULL;
		if (get_ParameterEntity(prefix, &entity) == 0)
			return 0;
	}

	if (name) {
		do {
			free(name);
			err++;
		} while (get_ParameterName(NULL, next_level, &name) == 0);
	}
	return err;
}

int get_ParameterIsWritable(char *name, int *isW)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	*isW = 0;
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	if (entity->flag & CWMP_WRITE)
		*isW = 1;
	return 0;
}

int get_ParameterIsReadable(char *name, int *isR)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	*isR = 0;
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	if (entity->flag & CWMP_READ)
		*isR = 1;
	return 0;
}

int get_ParameterValue(char *name, int *type, void **value)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	*value = NULL;
	*type = eCWMP_tNONE;
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	if ((entity->type != eCWMP_tOBJECT) && (entity->flag & CWMP_READ) && (entity->getvalue != NULL))
		return entity->getvalue(name, entity, type, value);

	return ERR_9003;	//object has no value to get
}

int set_ParameterValue(char *name, int type, void *value)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	if ((entity->type != eCWMP_tOBJECT) && (entity->flag & CWMP_WRITE) && (entity->setvalue != NULL))
		return entity->setvalue(name, entity, type, value);
	
	return ERR_9008;
}

int set_PrivateParameterValue(char *name, int type, void *value)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	//no need to check the writable flag
	if ((entity->type != eCWMP_tOBJECT) && (entity->setvalue != NULL))
		return entity->setvalue(name, entity, type, value);

	return ERR_9003;
}

int get_ParameterNotification(char *name, int *value)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	*value = 0;		/*default value */
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	if (entity->flag & CWMP_NTF_PAS)
		*value = 1;
	else if (entity->flag & CWMP_NTF_ACT)
		*value = 2;
	return 0;
}

int set_ParameterNotification(char *name, int value)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;

	//entity->flag = entity->flag & ( (CWMP_NTF_PAS|CWMP_NTF_ACT)^0xffff );
	if (value == 0)		//CWMP_NTF_OFF
		entity->flag = entity->flag & (~CWMP_NTF_MASK);	/*default value=0 */
	else if (value == 1)	//CWMP_NTF_PAS
		entity->flag = (entity->flag & (~CWMP_NTF_MASK)) | CWMP_NTF_PAS;
	else if (value == 2)	//CWMP_NTF_ACT
		entity->flag = (entity->flag & (~CWMP_NTF_MASK)) | CWMP_NTF_ACT;
	else
		return ERR_9007;

	return 0;
}

int get_ParameterAccessList(char *name, unsigned int *access)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (access == NULL)
		return -1;
	*access = 0;
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;
	*access = entity->flag & CWMP_ACS_MASK;
	return 0;
}

int set_ParameterAccessList(char *name, unsigned int access)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;

	//check if entity->type == object , return request reject
	entity->flag = entity->flag & ((~CWMP_ACS_MASK) | (access & CWMP_ACS_MASK));
	return 0;
}

int add_ParameterObject(char *name, unsigned int *number)
{
	struct sCWMP_ENTITY *entity;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if ((name == NULL) || (number == NULL))
		return ERR_9003;
	if (get_ParameterEntity(name, &entity) < 0)
		return ERR_9005;

	*number = 0;
	if ((entity->type == eCWMP_tOBJECT)
	    && (entity->flag & CWMP_WRITE)
	    && (entity->setvalue != NULL))
		return entity->setvalue(name, entity, eCWMP_tADDOBJ, number);

	return ERR_9001;
}

int del_ParameterObject(char *name)
{
	int number;
	struct sCWMP_ENTITY *entity;
	char *new_name;
	int ret = ERR_9005;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (name == NULL)
		return ERR_9005;
	// change name="xxx.3."  to new_name="xxx" & number = 3
	if (getPathAndObjNum(name, &new_name, &number) < 0)
		return ERR_9005;

	if (number > 0) {
		if (get_ParameterEntity(new_name, &entity) == 0) {
			if ((entity->type == eCWMP_tOBJECT)
			    && (entity->flag & CWMP_WRITE)
			    && (entity->setvalue != NULL))
				ret = entity->setvalue(new_name, entity, eCWMP_tDELOBJ, &number);
			else
				ret = ERR_9001;
		}
	}
	free(new_name);
	return ret;
}

//APACRTL-483
void save2flash_reboot(int reboot_flag, int apply)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));

#ifdef __DAVO__
	if (apply)
		nvram_commit();
#endif

	if (reboot_flag) {
#ifdef __DAVO__
		while (usleep(200000) > 0) ;
		kill(1, SIGTERM);
#endif
		exit(0);
	}

	return;
}

void factoryreset_reboot(void)
{
	//nvram_set("restore_defaults", "1");
	//save2flash_reboot(1);
	nvram_commit();
	yfecho("/proc/load_default", O_WRONLY, 0644, "1\n");
}

static void fstrcat(char *str, size_t size, const char *format, ...)
{
	va_list ap;
	size_t len = STRLEN(str);

	if (size > 0 && (size - 1) > len) {
		va_start(ap, format);
		vsnprintf(str + len, size - len, format, ap);
		va_end(ap);
	}
}

static void stepback(char *str)
{
	char *dot = strrchr(str, '.');
	if (dot)
		*dot = '\0';
	else
		str[0] = '\0';
}

static void traverse__table(struct sCWMP_ENTITY *root, int concat, int depth)
{
	static char buf[512];
	struct sCWMP_ENTITY *p, *q;
	int i;

	for (p = root; p && p->name[0]; p++) {
		for (i = 0; !concat && (i < (depth << 1)); i++)
			putchar(' ');

		if (p->sibling) {
			for (i = 0, q = p->sibling; q; q = q->sibling, i++) ;
			if (!concat)
				printf("[%d]\n", i + 1);
			else
				fstrcat(buf, sizeof(buf), ".[%d]", i + 1);
		} else {
			if (!concat)
				printf("%s\n", p->name);
			else
				fstrcat(buf, sizeof(buf), "%s%s", (buf[0] != '\0') ? "." : "", p->name);
		}

		if (p->next_table) {
			traverse__table(p->next_table, concat, depth + 1);
			if (concat)
				stepback(buf);
		} else if (concat) {
			printf("%s\n", buf);
			stepback(buf);
		}
	}
}

void traverse_table(int concat)
{
	traverse__table(pPrmtTableRoot, concat, 0);
}

long test_addr = 0;

void empty_data(int type, void **data)
{
	switch (type)
	{
		case eCWMP_tSTRING:
			*data = strdup("");
			break;
		case eCWMP_tINT:
			*data = intdup(0);
			break;
		case eCWMP_tUINT:
			*data = uintdup(0);
			break;
		case eCWMP_tBOOLEAN:
			*data = booldup(0);
			break;
		case eCWMP_tDATETIME:
			*data = timedup(0);
			break;
	}
}
#endif				/* __PARAMETER_API_C__ */
