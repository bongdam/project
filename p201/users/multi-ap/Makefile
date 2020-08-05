CONTROLLER_EXE             := map_controller
CONTROLLER_TEST_EXE        := map_controller_test
AGENT_EXE                  := map_agent
AGENT_TEST_EXE             := map_agent_test
MAP_CHECKER_EXE            := map_checker
HLE_EXE                    := hle_entity

################################################################################
# Targets
# ################################################################################

.PHONY: all
all: 

.PHONY: romfs
romfs:
	$(ROMFSINST) $(CONTROLLER_EXE) /bin/map_controller
	$(ROMFSINST) $(CONTROLLER_TEST_EXE) /bin/map_controller_test
	$(ROMFSINST) $(AGENT_EXE) /bin/map_agent
	$(ROMFSINST) $(AGENT_TEST_EXE) /bin/map_agent_test
	$(ROMFSINST) $(MAP_CHECKER_EXE) /bin/map_checker
	$(ROMFSINST) $(HLE_EXE) /bin/hle_entity
	$(ROMFSINST) multiap.conf /etc/multiap.conf
	$(ROMFSINST) lib/libmultiap.so /lib
