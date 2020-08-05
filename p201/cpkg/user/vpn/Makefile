subdirs = accel-pptp gmp strongswan xl2tpd

all: $(subdirs)

$(subdirs):
	@[ ! -d $@ ] || $(MAKE) -C $@

%:
	@for dir in $(subdirs); do [ ! -d $$dir ] || $(MAKE) -C $$dir $@; done

.PHONY: all $(subdirs)
