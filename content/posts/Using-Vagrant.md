---
title: Using Vagrant
Date: 2016-10-31
tags: [tools]
draft: false
---
## Why
When I started to learn about buffer overflows and memory exploits etc I found
that lots of the tutorials and material left out the details of environment
specifics. Therefore when I came to follow through the tutorials I ended up with
radically different results, got confused and felt like giving up.

## Virtualisation FTW
These days it is easy to run virtual machines and Oracle's virtualbox is free to
use and is stable enough to not have caused me too many issues.

See [here](https://www.virtualbox.org/wiki/Downloads) to download and view
install instructions for your platform

## Vagrant
What you quickly learn is that virtual machines take up a lot of space and
become a pain in the butt to manage the configs etc. In step [vagrant](https://www.vagrantup.com/)
to save the day.

Vagrant allows you to specify the box config & software setup all within a ruby
file (Named Vagrantfile) and run a couple of commands and you can then ssh into
your new environment.

To initialize a new machine cd into a directory where you will be working and
issue
```
  $ vagrant init
```
The above command generates a Vagantfile in the current directory. You edit the
config.vm.box to be a base box you desire (read docs for more info) which you
can find [here](https://atlas.hashicorp.com/boxes/search). You then run
```
  $ vagrant up
```
which will then download the base box, create you an instance of it and allow
you to ssh into it using the command
```
  $ vagrant ssh
```
Now you can do much, much more but one of the interesting feature is the ability
to automatically run provisioning scripts. 

Below is the Vagrantfile I use for learning memory exploits, it uses ubuntu
precise 32bit for its base and I install git, pip, peda (gdb plugin) and gdb to
help with debugging. Vagrant also mounts the current directory at /vagrant on
the guest so you can share your code with the guest OS.

{{< highlight ruby >}}
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "hashicorp/precise32"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
  end
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y git
    apt-get install -y gdb
    apt-get install -y python-pip
    apt-get install -y build-essential
    git clone https://github.com/longld/peda.git /home/vagrant/peda
    chown -R vagrant:vagrant /home/vagrant/peda
    echo "source ~/peda/peda.py" >> /home/vagrant/.gdbinit
    chown vagrant:vagrant /home/vagrant/.gdbinit
    pip install ropgadget
  SHELL
end
{{< / highlight >}}

As you can see this is just a matter of running the relevant shell commands to
install the required software

Couple this with github and you can have numerous configurations of machines at
your fingertips and only download the box files etc when you need them. Vargrant
allows you to have a consistent environment throughout all your development /
research.

Once your down with the machine just run
```
  $ vagrant halt
  $ vagrant destroy
```
remember destroy really does delete the VM so remember to do all the work you
want to keep in /vagrant or remember to copy it off of the vm in someway (iethub
etc) before you do this.
