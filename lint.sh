#!/bin/bash

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden
LINT=${LINT:-pylint}
exec ${LINT} --rcfile pylintrc --load-plugins=diagnose.pylint_plugin ${@:-diagnose}
