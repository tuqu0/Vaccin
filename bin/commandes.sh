#!/bin/bash

# log filename =>" hostname".txt
LOG=`hostname`".txt"

# put your commands here
echo $LOG
echo `whoami` >> $LOG
ls >> $LOG

