/* $Id: upnpdescstrings.h,v 1.9 2013/12/13 12:50:54 nanard Exp $ */
/* miniupnp project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2013 Thomas Bernard
 * This software is subject to the coditions detailed in
 * the LICENCE file provided within the distribution */
#ifndef UPNPDESCSTRINGS_H_INCLUDED
#define UPNPDESCSTRINGS_H_INCLUDED

#include "config.h"

/* strings used in the root device xml description */
#define ROOTDEV_FRIENDLYNAME		X_MAKER " " X_MODEL
#define ROOTDEV_MANUFACTURER		X_MAKER
#define ROOTDEV_MANUFACTURERURL		X_HOMEPAGE
#define ROOTDEV_MODELNAME			X_MODEL
#define ROOTDEV_MODELDESCRIPTION	ROOTDEV_FRIENDLYNAME
#define ROOTDEV_MODELURL			X_HOMEPAGE

#define WANDEV_FRIENDLYNAME			"WANDevice"
#define WANDEV_MANUFACTURER			"UPnP"
#define WANDEV_MANUFACTURERURL		X_HOMEPAGE
#define WANDEV_MODELNAME			"WAN Device"
#define WANDEV_MODELDESCRIPTION		"WAN Device"
#define WANDEV_MODELNUMBER			UPNP_VERSION
#define WANDEV_MODELURL				X_HOMEPAGE
#define WANDEV_UPC					"000000000000"
/* UPC is 12 digit (barcode) */

#define WANCDEV_FRIENDLYNAME		"WANConnectionDevice"
#define WANCDEV_MANUFACTURER		WANDEV_MANUFACTURER
#define WANCDEV_MANUFACTURERURL		WANDEV_MANUFACTURERURL
#define WANCDEV_MODELNAME			"UPnPd"
#define WANCDEV_MODELDESCRIPTION	"UPnP daemon"
#define WANCDEV_MODELNUMBER			UPNP_VERSION
#define WANCDEV_MODELURL			X_HOMEPAGE
#define WANCDEV_UPC					"000000000000"
/* UPC is 12 digit (barcode) */

#endif

