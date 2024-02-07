# NetTrace

### Building
To build the container, you can run the following command:
```bash
docker build -t netrace:latest .
```

### Running
On linux based systems, you can run the following command to run the container with the necessary permissions to capture packets on the host network interface:
```bash
docker run -ti --cap-add BPF --cap-add NET_ADMIN --cap-add CAP_PERFMON --cap-add NET_RAW --net=host netrace:latest -i any
```

On Windows or MacOS, You can't share the host network with a container on these systems because in these systems, the docker daemon runs inside a VM and the host network is not accessible from the containers.

You'll need to spin up a virtual machine with a linux distribution and run the command above or install the necessary dependencies directly inside the VM.