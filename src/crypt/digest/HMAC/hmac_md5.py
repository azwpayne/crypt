#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @time    : 2025/12/24 13:29
# @name    : hmac_md5.py
# @author  : azwpayne
# @desc    :

import hashlib
import hmac

key1 = '4f57585144435e435736363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636'
key2 = '253d323b2e2934293d5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c'

inputStr = 'hello'

str1 = bytes.fromhex(key1) + inputStr.encode()  # 第一次加盐
sign1 = hashlib.md5(str1).hexdigest()  # 第一次hash
print('sign1', sign1)

str2 = bytes.fromhex(key2) + bytes.fromhex(sign1)  # 第二次加盐
sign2 = hashlib.md5(str2).hexdigest()  # # 第二次hash
print('sign2', sign2)

sign = hmac.new('yangruhua'.encode(), 'hello'.encode(), hashlib.md5).hexdigest()
print('sign', sign)
