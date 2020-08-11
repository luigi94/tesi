#!/bin/bash
declare -a arr=("libssl-dev" "libboost-all-dev" "m4" "libreadline-dev" "flex" "bison" "libglib2.0-dev" )
for package in "${arr[@]}"
	do
		dpkg -i "$package"/*.deb
	done
