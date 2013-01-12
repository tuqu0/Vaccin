#!/bin/bash

# log filename => "hostname".txt
LOG=`hostname`".txt"

# put your commands here
ls >> $LOG
