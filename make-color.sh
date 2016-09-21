#!/bin/bash

# Colorize gcc output.
#
# Inspired from:
#  - http://vmrob.com/colorized-makefiles/
#  - https://gist.github.com/vmrob/8924878

# no color if stdout isn't a terminal
if [ -t 1 ]; then
	NO_COLOR="\033[0m"
	OK_COLOR="\033[32;01m"
	ERROR_COLOR="\033[31;01m"
	WARN_COLOR="\033[33;01m"
else
	NO_COLOR=''
	OK_COLOR=''
	ERROR_COLOR=''
	WARN_COLOR=''
fi

OK_STRING="${OK_COLOR}[OK]${NO_COLOR}"
ERROR_STRING="${ERROR_COLOR}[ERRORS]${NO_COLOR}"
WARN_STRING="${WARN_COLOR}[WARNINGS]${NO_COLOR}"

function awk_cmd {
	awk '{ printf " %-25s %-30s\n", $2, $1; }'
}

function print_error {
	echo -e "$@ ${ERROR_STRING}" | awk_cmd && echo -e "${CMD}\n${LOG}\n" && false
}

function print_warning {
	echo -e "$@ ${WARN_STRING}" | awk_cmd && echo -e "${CMD}\n${LOG}\n"
}

function print_ok {
	echo -e "$@ ${OK_STRING}" | awk_cmd
}

function get_gcc_outfile {
	outfile='???'
	while [ "${1+defined}" ]; do
		if [ "$1" = '-o' ]; then
			outfile=$2
			break
		fi
		shift
	done

	# get absolute path
	DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
	outfile="$PWD/$outfile"
	outfile=$(readlink -m "$outfile")    # avoid ../ in path
	outfile=${outfile##$DIR/}            # remove pwd from path
}

get_gcc_outfile $@

LOG=$($@ 2>&1)
if [ $? -eq 1 ]; then
	print_error $outfile
elif [ "x$LOG" != "x" ]; then
	print_warning $outfile
else
	print_ok $outfile
fi
