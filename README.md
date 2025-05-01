## How to run the project

**make topo:**

Starts mininet topology


**make app:**

Starts the controller.
The default pox directory is set to '/opt/pox/'.
However one should be able to overwrite it using make input.

Example:
`$ make poxdir=/pox/base/directory/ app`

**make test:**

Restarts topology, and the sdn controller. Then it runs provided test scenarios.

**make clean:**

Removes all junks added to different directories to run the application.
