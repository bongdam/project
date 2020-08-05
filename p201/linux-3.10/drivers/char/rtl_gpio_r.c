#include <generated/autoconf.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <asm/errno.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/reboot.h>
#include <linux/kmod.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include "bspchip.h"

#include <linux/seq_file.h>
#include <brdio.h>
#include <os_util.h>
#include <dvflag.h>

#define tohexa_1(x...)	0x##x
#define tohexa(x...)	tohexa_1(x)

#define INFINITE (~0U)

#define POLLING_PERIOD_CAPPED_MSEC 1000
#define msecs_to_tick(msecs) ((HZ * (msecs) + 999) / 1000)
#define elapsed(a) ((long)jiffies - (long)(a))

#define PWORK_PAUSE	(1 << 0)
#define PWORK_MFG	(1 << 1)

struct polling_work_struct {
	struct list_head list;
	int (*ctor)(struct polling_work_struct *);
	void (*dtor)(struct polling_work_struct *);
	void (*work)(struct polling_work_struct *);
	void (*mwork)(struct polling_work_struct *);
	void *data;
	unsigned long flags;
	int granule;
};

static int btn_group_lock;

enum {
	BTN_MFG_RELEASED,
	BTN_MFG_PRESSED,
	BTN_MFG_FROZEN = 100
};

enum {
	BTN_RELEASED,
	BTN_CHK_RELEASED,
	BTN_PRESSED,
	BTN_PSEUDO_PRESSED,
	BTN_CHK_PRESSED,
	BTN_LONG_PRESSED,
	BTN_CHK_RELEASED_2,
	BTN_FROZEN
};

enum {
	SWITCH_OFF = BTN_RELEASED,
	SWITCH_THRESH_OFF = BTN_CHK_RELEASED,
	SWITCH_ON = BTN_PRESSED,
	SWITCH_THRESH_ON = BTN_CHK_PRESSED
};

struct profile_button {
	int state;
	unsigned long pressed_ts;
	unsigned long mfg_ts;
	char gpio_name[4];
	char alias[16];
	char *cmdline;
};

#ifdef RESET_BTN_GPIO
static struct profile_button profile_rst_btn = { .alias = "RESET" };

static int init_reset_btn(struct polling_work_struct *pwork)
{
	pwork->data = &profile_rst_btn;
	profile_rst_btn.state = BTN_RELEASED;
	strncpy(profile_rst_btn.gpio_name, __stringify(RESET_BTN_GPIO), sizeof(profile_rst_btn.gpio_name));
	return sys_gpio_operate(__GPIOCIN, profile_rst_btn.gpio_name, NULL);
}

static void poll_reset_button(struct polling_work_struct *pwork)
{
	struct profile_button *p = (struct profile_button *)pwork->data;
	int pressed = 0;

#if defined(IP04438A)
	if (unlikely(p->state == BTN_FROZEN)) {
		if (!(dvflag_get() & DF_RSTASSERTED)) {
			dvflag_set(DF_RSTASSERTED, DF_RSTASSERTED);
			pwork->flags |= PWORK_PAUSE;
		}
		pwork->granule = msecs_to_tick(1000);
		return;
	}
#endif
	sys_gpio_operate(__GPIOGACTIVE, p->gpio_name, &pressed);
#if !defined(IP04438A)
	if (unlikely(p->state == BTN_FROZEN)) {
		if (pressed == 0) {
			dvflag_set(DF_RSTASSERTED, DF_RSTASSERTED);
			pwork->flags |= PWORK_PAUSE;
		}
	} else
#endif /* !IP04438A */
	if (likely(btn_group_lock == false)) {
		switch (p->state) {
		case BTN_RELEASED:
			if (unlikely(pressed)) {
				p->state = BTN_PRESSED;
				p->pressed_ts = jiffies;
			}
			break;
		case BTN_PRESSED:
			if (pressed == 0) {
				p->state = BTN_RELEASED;
#if (tohexa(WPS_BTN_GPIO) == tohexa(RESET_BTN_GPIO))
				if (elapsed(p->pressed_ts) < msecs_to_tick(1000))
					break;
				p->pressed_ts = jiffies;
				p->state = BTN_PSEUDO_PRESSED;
#else
				if (elapsed(p->pressed_ts) < msecs_to_tick(3000))
					kill_pid(get_pid(find_vpid(1)), SIGTERM, 1);
#endif
			} else if (dvflag_get() & (DF_REBOOTING | DF_UPLOADING))
				p->state = BTN_RELEASED;
			else if (!(dvflag_get() & DF_WPSASSERTED) &&
			         elapsed(p->pressed_ts) >= msecs_to_tick(3000))
				dvflag_set(DF_WPSASSERTED, DF_WPSASSERTED);
#if (tohexa(WPS_BTN_GPIO) == tohexa(RESET_BTN_GPIO))
			else if (elapsed(p->pressed_ts) >= msecs_to_tick(180000))
#else
			else if (elapsed(p->pressed_ts) >= msecs_to_tick(5000))
#endif
			{
				p->state = BTN_FROZEN;
				p->pressed_ts = jiffies;
				btn_group_lock = true;
			}
			break;
#if (tohexa(WPS_BTN_GPIO) == tohexa(RESET_BTN_GPIO))
		case BTN_PSEUDO_PRESSED:
			/* Must be enough to pass button_hold_time in wscd.conf */
			if (elapsed(p->pressed_ts) >= msecs_to_tick(2000))
				p->state = BTN_RELEASED;
			break;
#endif
		default:
			break;
		}
	}

	pwork->granule = (p->state == BTN_RELEASED)
		? msecs_to_tick(500) : msecs_to_tick(100);
}
#endif

#if defined(RESET_BTN_GPIO) || defined(WPS_BTN_GPIO)
static unsigned long mfg_time_span;

static void poll_mfg_button(struct polling_work_struct *pwork)
{
	struct profile_button *p = (struct profile_button *)pwork->data;
	int pressed = 0;

	sys_gpio_operate(__GPIOGACTIVE, p->gpio_name, &pressed);
	switch (p->state) {
	case BTN_MFG_RELEASED:
		if (pressed) {
			p->state = BTN_MFG_PRESSED;
			p->pressed_ts = jiffies;
		}
		break;
	case BTN_MFG_PRESSED:
		if (!pressed)
			p->state = BTN_MFG_RELEASED;
		else if (elapsed(p->pressed_ts) >= msecs_to_tick(200))
			p->state = BTN_MFG_FROZEN;
		break;
	case BTN_MFG_FROZEN:
		if (mfg_time_span && (elapsed(p->mfg_ts) >= mfg_time_span)) {
#if 0
			pwork->flags &= ~PWORK_MFG;
			pwork->granule = msecs_to_tick(500);
			p->state = BTN_RELEASED;
#endif
			return;
		}
		break;
	}
	pwork->granule = msecs_to_tick(100);
}
#endif

#if defined(WPS_BTN_GPIO) && (!defined(RESET_BTN_GPIO) || (tohexa(WPS_BTN_GPIO) != tohexa(RESET_BTN_GPIO)))
static struct profile_button profile_wps_btn = { .alias = "WPS" };

static int init_wps_btn(struct polling_work_struct *pwork)
{
	pwork->data = &profile_wps_btn;
	strncpy(profile_wps_btn.gpio_name, __stringify(WPS_BTN_GPIO), sizeof(profile_wps_btn.gpio_name));
	return sys_gpio_operate(__GPIOCIN, profile_wps_btn.gpio_name, NULL);
}

static void poll_wps_button(struct polling_work_struct *pwork)
{
	struct profile_button *p = (struct profile_button *)pwork->data;
	int pressed = 0;

	if (unlikely(btn_group_lock == true))
		return;

	sys_gpio_operate(__GPIOGACTIVE, p->gpio_name, &pressed);

	switch (p->state) {
	case BTN_RELEASED:
		if (unlikely(pressed)) {
			p->state = BTN_CHK_PRESSED;
			p->pressed_ts = jiffies;
		}
		break;
	case BTN_CHK_PRESSED:
		if (unlikely(pressed == 0))
			p->state = BTN_RELEASED;
		else if (elapsed(p->pressed_ts) >= msecs_to_tick(400)) {
			p->state = BTN_PRESSED;
			p->pressed_ts = jiffies;
		}
		break;
	case BTN_PRESSED:
		if (pressed == 0) {
			p->state = BTN_CHK_RELEASED;
			p->pressed_ts = jiffies;
		}
		break;
	case BTN_CHK_RELEASED:
		if (pressed)
			p->state = BTN_PRESSED;
		else if (elapsed(p->pressed_ts) >= msecs_to_tick(100))
			p->state = BTN_RELEASED;
		else
			break;
		p->pressed_ts = jiffies;
		break;
	default:
		break;
	}

	pwork->granule = (p->state == BTN_RELEASED)
			? msecs_to_tick(500) : msecs_to_tick(100);
}
#endif

static struct polling_work_struct regular_pworks[] = {
#ifdef RESET_BTN_GPIO
	{
	 .ctor = init_reset_btn,
	 .work = poll_reset_button,
	 .mwork = poll_mfg_button,
	},
#endif
#if defined(WPS_BTN_GPIO) && (!defined(RESET_BTN_GPIO) || (tohexa(WPS_BTN_GPIO) != tohexa(RESET_BTN_GPIO)))
	{
	.ctor = init_wps_btn,
	.work = poll_wps_button,
	.mwork = poll_mfg_button,
	},
#endif
};

static struct timer_list polling_work_timer;
static int polling_work_granule;
static LIST_HEAD(polling_works_head);
static DEFINE_SPINLOCK(polling_works_lock);

/* intstrument API to do polling work
 */
/* the Greatest Common Denominator */
static inline int simple_gcd(int u, int v)
{
	int t;

	while (u) {
		if (u < v) {
			t = u;
			u = v;
			v = t;
		}
		u = u - v;
	}
	return v;
}

static int __register_polling_work(struct polling_work_struct *pwork)
{
	if (pwork->ctor && pwork->ctor(pwork))
		return -1;
	list_add_tail_rcu(&pwork->list, &polling_works_head);
	return 0;
}

static int register_polling_work(struct polling_work_struct *pwork) __attribute__ ((unused));
static int register_polling_work(struct polling_work_struct *pwork)
{
	int ret;

	spin_lock_bh(&polling_works_lock);
	ret = __register_polling_work(pwork);
	spin_unlock_bh(&polling_works_lock);
	return ret;
}

static void __unregister_polling_work(struct polling_work_struct *pwork)
{
	if (pwork->dtor)
		pwork->dtor(pwork);
	list_del_rcu(&pwork->list);
}

static void unregister_polling_work(struct polling_work_struct *pwork)
{
	spin_lock_bh(&polling_works_lock);
	__unregister_polling_work(pwork);
	spin_unlock_bh(&polling_works_lock);
	synchronize_rcu();
}

static void run_polling_work(unsigned long data)
{
	struct polling_work_struct *pwork;
	int gcd = msecs_to_tick(POLLING_PERIOD_CAPPED_MSEC);

	rcu_read_lock();
	list_for_each_entry_rcu(pwork, &polling_works_head, list) {
		if (likely((pwork->flags & PWORK_PAUSE) == 0)) {
			if (likely((pwork->flags & PWORK_MFG) == 0))
				pwork->work(pwork);
			else if (pwork->mwork)
				pwork->mwork(pwork);
		}
		if (pwork->granule > 0)
			gcd = simple_gcd(gcd, pwork->granule);
	}
	rcu_read_unlock();

	mod_timer(&polling_work_timer, jiffies + gcd);
	polling_work_granule = gcd;
}

static void exit_polling_work(void)
{
	struct polling_work_struct *pwork;

	del_timer_sync(&polling_work_timer);

	spin_lock_bh(&polling_works_lock);
	list_for_each_entry_rcu(pwork, &polling_works_head, list)
		unregister_polling_work(pwork);
	spin_unlock_bh(&polling_works_lock);
}

static int init_polling_work(void)
{
	int i;

	spin_lock_bh(&polling_works_lock);
	for (i = 0; i < ARRAY_SIZE(regular_pworks); i++)
		__register_polling_work(&regular_pworks[i]);
	spin_unlock_bh(&polling_works_lock);
	setup_timer(&polling_work_timer, run_polling_work, 0);
	mod_timer(&polling_work_timer, jiffies + msecs_to_jiffies(POLLING_PERIOD_CAPPED_MSEC));
	return 0;
}

static int gpio_rproc(struct seq_file *m, void *data)
{
#ifdef WPS_BTN_GPIO
	struct profile_button *p = (struct profile_button *)data;
# if defined(RESET_BTN_GPIO) && (tohexa(WPS_BTN_GPIO) == tohexa(RESET_BTN_GPIO))
	return seq_printf(m, "%u\n", !!(p->state == BTN_PSEUDO_PRESSED));
# else
	return seq_printf(m, "%u\n", !!(p->state == BTN_PRESSED));
# endif
#else
	return seq_printf(m, "0\n");
#endif
}

static int gpio_wproc(const char *buffer, size_t count, void *data)
{
	char flag[20];
	/* count variable would be decremented till zero.
	 * Be careful not to return 0 then write operation would be unended.
	 */
	int cmd, rtn = count;

	while (gets_from_user(flag, sizeof(flag), &buffer, (int *)&count)) {
		switch ((cmd = flag[0])) {
		case '0':	// Off WPS LED
			dvflag_set(0, DF_WPSASSERTED);
			break;
		case '1':
			// On WPS LED
			break;
		case '2':	// Blink WPS LED
			if (!(dvflag_get() & DF_WPSASSERTED))
				dvflag_set(DF_WPSASSERTED, DF_WPSASSERTED);
			break;
		case '4':	/* Reboot Wait Amount */
		default:
			break;
		}
	}
	return rtn;
}

static struct proc_dir_thunk gpio_top = {
#if defined(WPS_BTN_GPIO)
# if defined(RESET_BTN_GPIO) && (tohexa(WPS_BTN_GPIO) == tohexa(RESET_BTN_GPIO))
 	.data = (void *)&profile_rst_btn,
# else
 	.data = (void *)&profile_wps_btn,
# endif
#endif
	.read_proc = gpio_rproc,
	.write_proc = gpio_wproc,
};

static int load_dfl_rproc(struct seq_file *m, void *data)
{
#ifdef RESET_BTN_GPIO
	return seq_printf(m, "%d\n", !!(dvflag_get() & DF_RSTASSERTED));
#else
	return seq_printf(m, "0\n");
#endif
}

static int load_dfl_wproc(const char *buffer, size_t count, void *data)
{
#ifdef RESET_BTN_GPIO
	struct profile_button *p = (struct profile_button *)data;
	char tmp[16];

	if (strtrim_from_user(tmp, sizeof(tmp), buffer, count) > 0) {
		spin_lock_bh(&polling_works_lock);
		if (btn_group_lock) {
			spin_unlock_bh(&polling_works_lock);
			return -EACCES;
		}
		p->state = BTN_FROZEN;
		p->pressed_ts = jiffies;
		btn_group_lock = true;
		spin_unlock_bh(&polling_works_lock);
	}
#endif
	return count;
}

static struct proc_dir_thunk load_dfl_top = {
#ifdef RESET_BTN_GPIO
	.data = (void *)&profile_rst_btn,
#endif
	.read_proc = load_dfl_rproc,
	.write_proc = load_dfl_wproc,
};

#ifdef RESET_BTN_GPIO
static int mfg_btn_rproc(struct seq_file *m, void *data)
{
	struct polling_work_struct *pwork;
	struct profile_button *p;

	spin_lock_bh(&polling_works_lock);
	list_for_each_entry_rcu(pwork, &polling_works_head, list) {
		if (pwork->mwork) {
			p = (struct profile_button *)pwork->data;
			seq_printf(m, "%s %d %d\n", p->alias, (p->state == BTN_MFG_FROZEN), p->state);
		}
	}
	spin_unlock_bh(&polling_works_lock);
	return 0;
}

static int mfg_btn_wproc(const char *buffer, size_t count, void *data)
{
	struct polling_work_struct *pwork;
	struct profile_button *p;
	char tmp[16];

	if (strtrim_from_user(tmp, sizeof(tmp), buffer, count) > 0) {
		mfg_time_span = simple_strtoul(tmp, NULL, 0) * HZ;
		spin_lock_bh(&polling_works_lock);
		if (btn_group_lock) {
			spin_unlock_bh(&polling_works_lock);
			return -EACCES;
		}
		list_for_each_entry_rcu(pwork, &polling_works_head, list) {
			if (pwork->mwork) {
				p = (struct profile_button *)pwork->data;
				pwork->granule = msecs_to_tick(100);
				if (mfg_time_span > 0) {
					pwork->flags |= PWORK_MFG;
					p->state = BTN_MFG_RELEASED;
					p->mfg_ts = jiffies;
				} else {
					pwork->flags &= ~PWORK_MFG;
					p->state = BTN_RELEASED;
				}
			}
		}
		spin_unlock_bh(&polling_works_lock);
	}
	return count;
}

static struct proc_dir_thunk mfg_btn_top = {
	.data = (void *)&profile_rst_btn,
	.read_proc = mfg_btn_rproc,
	.write_proc = mfg_btn_wproc,
};
#endif

static inline void gpio_led_set_value(const char *name, int value)
{
	sys_gpio_operate(value ? __GPIOSACTIVE : __GPIOSINACT, name, NULL);
}

enum {
	LED_OP_BLINK_ON,
	LED_OP_BLINK_OFF,
	LED_OP_OFF,
	LED_OP_ON,
};

typedef unsigned int msec_t;

struct led_blink {
	struct list_head	list;		/* MUST be the first */
	long			id;
	unsigned int		delay_on;
	unsigned int		delay_off;
	unsigned int		count;
	short			op;
	short			priority;	/* the bigger the higher */
	unsigned long		expiry;
	struct rcu_head		rcu;
};

/*
 * SYS/CPU LED management
 */
struct led_blink_priority_list {
	struct list_head	head;
	spinlock_t		lock;
	const char		*name; /* gpio name */
	struct timer_list	timer;
	long			top_id;
};

static void poll_led_timer_callback(struct led_blink_priority_list *);
static struct led_blink_priority_list status_led_blinker = {
	.head = LIST_HEAD_INIT(status_led_blinker.head),
	.lock =	__SPIN_LOCK_UNLOCKED(status_led_blinker.lock),
	.timer = TIMER_INITIALIZER((void (*)(ulong))poll_led_timer_callback,
		0, (ulong)&status_led_blinker),
	.name = __stringify(SYS_LED_GPIO),
};

static void led_blink_rcu_free(struct rcu_head *head)
{
	struct led_blink *p = container_of(head, struct led_blink, rcu);
	kfree(p);
}

static void led_blink_delete(struct led_blink *p)
{
	list_del_rcu(&p->list);
	call_rcu(&p->rcu, led_blink_rcu_free);
}

static struct led_blink *led_blink_create(msec_t delay_on,
					  msec_t delay_off,
					  unsigned int count,
					  short priority,
					  int first_off)
{
	static long id = 0;
	struct led_blink *p;

	p = (struct led_blink *)kmalloc(sizeof(*p), GFP_ATOMIC);
	if (p) {
		p->id = ++id;
		p->priority = priority;
		p->count = count;
		p->expiry = jiffies;
		if (delay_on == INFINITE) {
			p->delay_on = INFINITE;
			p->delay_off = 0;
			p->op = LED_OP_ON;
		} else if (delay_off == INFINITE) {
			p->delay_on = 0;
			p->delay_off = INFINITE;
			p->op = LED_OP_OFF;
		} else {
			p->delay_on = msecs_to_tick(delay_on);
			p->delay_off = msecs_to_tick(delay_off);
			p->op = first_off ? LED_OP_BLINK_ON : LED_OP_BLINK_OFF;
		}
	}
	return p;
}

static void led_blink_insert(struct led_blink *newp, struct led_blink_priority_list *qu)
{
	struct led_blink *p;
	struct list_head *prev = &qu->head;

	spin_lock_bh(&qu->lock);
	list_for_each_entry_rcu(p, &qu->head, list) {
		if (p->priority == newp->priority) {
			list_replace_rcu(&p->list, &newp->list);
			call_rcu(&p->rcu, led_blink_rcu_free);
			goto out;
		} else if (p->priority < newp->priority)
			break;
		prev = &p->list;
	}
	list_add_rcu(&newp->list, prev);
out:
	spin_unlock_bh(&qu->lock);
}

static void poll_led_timer_callback(struct led_blink_priority_list *qu)
{
	struct led_blink *p, *t;
	long timeout, min_timeout = LONG_MAX;
	bool top = true;

	spin_lock(&qu->lock);
	list_for_each_entry_safe(p, t, &qu->head, list) {
		if (top && (qu->top_id != p->id)) {
			qu->top_id = p->id;
			gpio_led_set_value(qu->name,
				!!(p->op == LED_OP_ON || p->op == LED_OP_BLINK_ON));
		}
		switch (p->op) {
		case LED_OP_BLINK_ON:
		case LED_OP_BLINK_OFF:
			timeout = elapsed(p->expiry);
			if (timeout >= 0) {
				if (top)
					gpio_led_set_value(qu->name, !!(p->op == LED_OP_BLINK_OFF));
				if (unlikely(!p->count)) {
					led_blink_delete(p);
					// update LED at next tick
					timeout = 1;	// 1 tick
				} else {
					if (p->count != INFINITE)
						--p->count;
					timeout = (p->op == LED_OP_BLINK_OFF) ?
						  p->delay_on : p->delay_off;
					p->expiry = jiffies + timeout;
					p->op = (p->op == LED_OP_BLINK_OFF) ?
						 LED_OP_BLINK_ON : LED_OP_BLINK_OFF;
				}
			} else
				timeout = 0 - timeout;
			if (min_timeout > timeout)
				min_timeout = timeout;
			break;
		case LED_OP_OFF:
		case LED_OP_ON:
			if (top)
				gpio_led_set_value(qu->name, !!(p->op == LED_OP_ON));
			break;
		}
		top = false;
	}
	spin_unlock(&qu->lock);

	if (min_timeout != LONG_MAX)
		mod_timer(&qu->timer, jiffies + min_timeout);
}

static struct led_blink *status_led_blink_add(short priority,
					     unsigned int count,
					     msec_t delay_on,
					     msec_t delay_off,
					     int first_off)
{
	struct led_blink *p
		= led_blink_create(delay_on, delay_off, count, priority, first_off);
	if (likely(p != NULL)) {
		led_blink_insert(p, &status_led_blinker);
		mod_timer(&status_led_blinker.timer, jiffies + 1);
	}
	return p;
}

/* <prio> <count> <on> <off>
 * priority: the bigger priority is, the higher
 * count: sum of each on and off. if count reaches zero,
          specified priority will be removed
 * on: keep ON due for on msec
 * off: keep OFF due for off msec
 */
static int sysled_configure_set(const char *val,
				const struct kernel_param *kp)
{
	int prio, cnt, delay_on, delay_off, first_off = 0;
	if (sscanf(val, "%d %d %d %d %d", &prio, &cnt, &delay_on, &delay_off, &first_off) < 4)
		return -EINVAL;
	return status_led_blink_add(prio, cnt, delay_on, delay_off, first_off) ? 0 : -ENOMEM;
}

static inline unsigned int tick_to_msecs(unsigned int tick)
{
	return (tick != INFINITE) ? jiffies_to_msecs(tick) : INFINITE;
}

static int sysled_configure_get(char *buf, const struct kernel_param *kp)
{
	struct led_blink *p;
	char *buf_start = buf;

	rcu_read_lock();
	p = list_first_or_null_rcu(&status_led_blinker.head, struct led_blink, list);
	if (p)
		buf += sprintf(buf, "%d %d %d %d", p->priority, (int)p->count,
			       (int)tick_to_msecs(p->delay_on),
			       (int)tick_to_msecs(p->delay_off));
	rcu_read_unlock();
	return buf - buf_start;
}

static const struct kernel_param_ops sysled_configure_parm_ops = {
	.set = sysled_configure_set,
	.get = sysled_configure_get,
};

module_param_cb(sysled, &sysled_configure_parm_ops, NULL, 0644);

static int __init rtl_gpio_init(void)
{
	u32 value = 0;
	printk("Realtek GPIO Driver for Flash Reload Default\n");

	sys_gpio_operate(__GPIOCOUT, __stringify(SYS_LED_GPIO), &value);
	init_polling_work();
	create_proc_thunk("gpio", NULL, &gpio_top);
	create_proc_thunk("load_default", NULL, &load_dfl_top);
#ifdef RESET_BTN_GPIO
	create_proc_thunk("factory_btn_test", NULL, &mfg_btn_top);
#endif
	return 0;
}

static void __exit rtl_gpio_exit(void)
{
	remove_proc_entry("gpio", NULL);
	remove_proc_entry("load_default", NULL);
#ifdef RESET_BTN_GPIO
	remove_proc_entry("factory_btn_test", NULL);
#endif
	exit_polling_work();
}

module_exit(rtl_gpio_exit);
module_init(rtl_gpio_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPIO driver for Reload default");
