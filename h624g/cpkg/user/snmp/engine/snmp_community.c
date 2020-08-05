/* ====================================================================
 * Copyright (c) 1997 - 2000 
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
 * be found on http://www.simpleweb.org/software/packages/smash/.
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

#ifdef SNMP_CONFIG_H
#include "snmp_config.h"
#endif

//#include <mta.h>
//#include <cxcEnv.h>
//#include <cxcLog.h>
//#include <bosTask.h>
//#include <callclient.h>
//#include <cmmtaint.h>
//#include <xchgAssert.h>
//#include <dns.h>
//#include <netStr.h>
//#include <netCfg.h>

//#include <bosTask.h>
//#include <bosTime.h>
//#include <bosSocket.h>
//#include <bosSem.h>
//#include <bosMutex.h>

//#include <str.h>
//#include <network.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>


#include	"asn1.h"
#include	"snmp.h"
#include	"agt_engine.h"
#include	"snmp_community.h"

/*
typedef struct {
    char                        string[MAX_COMMUNITY_LEN];
    int                         length;
    int                         number;
    } Community_t;
*/

Community_t communities[ MAX_COMMUNITIES ] = {
	{"", 0, 0}, {"", 0, 0}, {"", 0, 0}, {"", 0, 0}, {"", 0, 0}, 
	{"", 0, 0}, {"", 0, 0}, {"", 0, 0}, {"", 0, 0}, {"", 0, 0}
};

int nr_communities = 0;

//char	*set_community(FILE *f, char *arg)
char *set_community(char *com)
{
	int i;

	for (i = 0; i < nr_communities ; i++) {
		if (0 == strcmp(communities[i].string, com)) {
			return(NULL);
		}
	}
	nr_communities++;
	strcpy(communities[i].string, com);
	communities[i].length = strlen(com);
	communities[i].number = nr_communities;
	return "Could not add community";
}


void ensure_communities(void)
{
	if(nr_communities == 0) {
		fprintf(stderr,"Warning: NO communities defined, SNMP access set to '" DEFAULT_COMM "' !\n");
		nr_communities = 1;
		strcpy(communities[0].string, DEFAULT_COMM);
		communities[0].length = strlen(DEFAULT_COMM);
		communities[0].number = 1;
	}
}

unsigned char	*snmp_parse_community(unsigned char *data, int *length,
		snmp_info_t *mesg)
{
	unsigned char type;
	int i;

	data = asn_parse_string(data, length, &type, 
			mesg->community, &(mesg->community_length));
	if (data == NULL){
		return NULL;
	}

	for (i  = 0 ; i < nr_communities ; i++){    	
		if ((mesg->community_length == communities[i].length) &&
		!(memcmp( (char *)mesg->community, communities[i].string, mesg->community_length))) {
			mesg->community_id = communities[i].number;
			return (unsigned char *)data;
		}
	}
	return (unsigned char *)data;
	//return NULL;
}


