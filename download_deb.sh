#!/bin/bash
declare -a arr=("libssl-dev" "libboost-all-dev" "m4" "libreadline-dev" "flex" "bison" "libglib2.0-dev" )
for package in "${arr[@]}"
	do
		dpkg -i "$package"/*.deb
	done
	
#!/bin/bash
declare -a arr=("libssl-dev" "libboost-all-dev" "libreadline-dev" "flex" "bison" "libglib2.0-dev" "m4")
for package in "${arr[@]}"
	do
		mkdir "$package"
		apt-get --print-uris --yes install "$package" | grep ^\' | cut -d\' -f2 > "$package/$package".txt
		wget --input-file "$package/$package".txt -P "$package"
		#dpkg -i *.deb
		#rm -rf *.deb
		#rm -rf "$package".txt
	done