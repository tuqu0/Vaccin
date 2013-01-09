#!/bin/bash

# log filename => "hostname".txt
LOG=`hostname`".txt"

# put your commands here
echo `whoami` >> $LOG
ls >> $LOG
