poxdir ?= /opt/pox/
results_dir := ./results/
results_file := $(results_dir)phase_1_report.txt
controller_file := $(results_dir)phase_1_controller_logs.txt


# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	mkdir -p results
	sudo python ./topology/topology.py

app:
	@echo "starting the baseController!"
	# Copy your controller to the POX folder
	cp applications/controller/* $(poxdir)ext/
	# Copy nfv click functions to the pox controller folder
	cp applications/nfv/*.click $(poxdir)ext/
	# Run controller that setups normal switches and CLICK nodes
	sudo python /opt/pox/pox.py baseController

test:
	@echo "starting test scenarios!"
	rm -rf $(results_dir)*
	mkdir -p $(results_dir)
	touch $(results_dir)ids.report
	touch $(results_dir)lb1.report
	touch $(results_dir)napt.report
	make app > $(controller_file) &
	sudo python ./topology/topology_test.py > $(results_file)

	sleep 10
	make clean

clean:
	@echo "project files removed from pox directory!"
	# Remove files from ext dir in pox
	rm -f $(poxdir)ext/baseController.py $(poxdir)ext/click_wrapper.py $(poxdir)ext/*.click
	# Kill controller
	@# use the regexp trick to not match grep itself. And ignore the error if no pox running
	kill `ps -ef | grep pox[.py] | awk '{print $$2}'` || true
	# Clean mininet
	sudo mn -c
	# Kill click processes
	sudo killall click

clean_results:
	@echo "results files removed!"
	rm -rf $(results_dir)*


