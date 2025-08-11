# Ruby CLI Server

<div align="center">
  <img src="img/server-logo.png" width=750px>
</div>

Local server written in Ruby to trace HTTP requests and store logs

---

## Install tool

* Download the script to your system

```shell
mkdir -p ~/RubyTools/Ruby-CLI-Server/ && cd $_
curl -O https://raw.githubusercontent.com/iTroxB/My-scripts/refs/heads/main/Ruby-CLI-Server/rubyCLIserver.rb
```

* Create symbolic link to the script

```shell
sudo ln -s ~/RubyTools/Ruby-CLI-Server/rubyCLIserver.rb /usr/bin/rubyCLIserver
```

* To know the options and parameters of the tool run the help menu with the flag `-h`

```shell
rubyCLIserver -h
```

<div align="center">
  <img src="img/server-help.png" width=750px>
</div>

---

## Use tool

- Execute server on port 9090

<div align="center">
  <img src="img/server-1.png" width=750px>
</div>

- Running server on port 9090 with output file

<div align="center">
  <img src="img/server-2.png" width=750px>
</div>