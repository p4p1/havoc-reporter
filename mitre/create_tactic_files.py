#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: Jakob Friedl
# Created on: Mon, 30. Oct. 2023
# Description: Reads MITRE data from json file and creates standalone python files

import json

file = "mitre.json"
tactics = []

with open(file, "r") as f:
    tactics = json.load(f)

for t in tactics: 
    tactic = t["tactic"].lower().replace(" ", "_")

    with open(tactic + ".py", "w") as f:
        f.write(tactic + " = ")
        json.dump(t["techniques"], f, ensure_ascii=False, indent=4)
