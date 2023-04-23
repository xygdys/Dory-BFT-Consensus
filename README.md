# Dory BFT Consensus
Implementation of four BFT consensus protocols: [Dory](https://eprint.iacr.org/2022/1709), [Dory-NG](https://eprint.iacr.org/2022/1709), [sDumbo](https://eprint.iacr.org/2022/027) and [Dumbo-NG](https://arxiv.org/abs/2209.00750).

In the following, we take Dory as an example to show how to run the code.
```
cd Dory
```

### Run the code Locally

You can launch a demo easily through the go test command:
```
go test -timeout 30s -run ^TestMainProgress$ Dory/internal/aab
```
By default, the above command will run a demo where N=4, F=1 for 2 epochs. You can adjust the parameters by editing `Dory/internal/aab/dory_test.go`.

### Depoly the Amazon EC2 experiment

1) Before depolying the code on the Amazon EC2 instances, you need to manually start the EC2 instances and record their IP addresses and port numbers. Then, configure the information of your instances in `Dory/config.yaml`. You can find an example in this file.
+ **N** means the total number of parties;
+ **F** means the tolerance, usually N=3F+1 in the experiments;
+ **IPList** means the IP list of the instances;
+ **PortList** means the port list of the instances;
+ **PrepareTime** means the preparation time before starting the experiment;
+ **WaitTime** means the waiting time after finishing the experiment.

2) Generate the keys. We provide a docker script to atomatically generate keys and configuration files for each instance:
```
docker compose up config_build
```
After that, you can find **N** configuration files with encoded keys in `Dory/configs`.

3) Compile and create an executable file. Run the following command and find the executable file `start` in `Dory/build`.
```
docker compose up main_build
```

4) Upload the executable file and the configuration file to the corresponding Amazon EC2 instance. For example, rename `config_0.yaml` to `config.yaml`, and upload it with `start` to the first EC2 instance. 

5) Run the executable files on EC2 instances. To start an experiment with the batch size 10000, run the following command simultaneously on the EC2 instances,
```
cd /home/ubuntu && nohup ./start 10000 > /dev/null 2>log &
```
You can do this through AWS SDK (such as [boto3](https://aws.amazon.com/sdk-for-python)). After the experiment ends, find the reports on your EC2 instances.


### LICENSE

 * Copyright (C) 2016-2017 Vivint, Inc.
 * Copyright (C) 2015 Klaus Post
 * Copyright (C) 2015 Backblaze
 * Copyright (C) 2011 Billy Brumley (billy.brumley@aalto.fi)
 * Copyright (C) 2009-2010 Jack Lloyd (lloyd@randombit.net)
 * Copyright (C) 1996-1998 Luigi Rizzo (luigi@iet.unipi.it)
