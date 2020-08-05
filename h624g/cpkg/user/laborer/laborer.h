#ifndef __LABORER_H__
#define __LABORER_H__

struct labor_house {
	void (*init)(void);
	void (*poll)(void);
	int *enable;
};

#endif
