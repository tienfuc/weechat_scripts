# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 by TienFu Chen <tienfu.c@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This script is forked from urlbuf, originally developed by Jani Kesänen <jani.kesanen@gmail.com>

"""
urlsave
"""
SCRIPT_NAME    = "urlsave"
SCRIPT_AUTHOR  = "TienFu Chen <tienfu.c@gmail.com>"
SCRIPT_VERSION = "0.1"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC    = "Save content from URLs."

import_ok = True

try:
    import weechat
except ImportError:
    print "This script must be run under WeeChat."
    import_ok = False

import re
import os
import urllib
from time import strftime
from datetime import datetime

octet = r'(?:2(?:[0-4]\d|5[0-5])|1\d\d|\d{1,2})'
ipAddr = r'%s(?:\.%s){3}' % (octet, octet)
# Base domain regex off RFC 1034 and 1738
label = r'[0-9a-z][-0-9a-z]*[0-9a-z]?'
domain = r'%s(?:\.%s)*\.[a-z][-0-9a-z]*[a-z]?' % (label, label)
url_re = re.compile(r'(\w*(?:://)?(?:%s|%s)(?::\d+)?(?:/[^\])>\s]*)?)' % (domain, ipAddr), re.I)

urlsave_buffer = None

urlsave_settings = {
    "display_private"       : ("on",    "display URLs from private messages"),
    "display_nick"          : ("off",   "display the nick of the user"),
    "skip_duplicates"       : ("on",    "skip the URL that is already in the urlsave"),
    "no_skips"              : ("on",    "display URLs from all buffers, override \'include_channels\'"),
    "include_channels"      : ("",      "a comma separated list of channels to save URLs"),
    "hook_command"          : ("/usr/bin/curl %s -o %s --create-dirs",   "a hook command for grabbed URLs, the first %s is URL, the second is output file"),
    "save_folder"           : ("urls",  "folder to save the content of URLs"),
    "convert_youtube"       : ("on",    "if convert youtube URL"),
    "convert_imgur"         : ("on",    "if convert imgur URL"),
    "convert_pastebin"      : ("on",    "if convert pastebin URL"),
    }

def is_url_listed(buffer, url):
    """ Search for the URL from the buffer lines. """
    infolist = weechat.infolist_get("buffer_lines", buffer, "")

    found = False
    while weechat.infolist_next(infolist):
        message = weechat.infolist_string(infolist, "message").split(' ')[-1]
        if message == url:
            found = True
            break

    weechat.infolist_free(infolist)

    return found

def convert_url(url, option):
    # if pastebin
    if "convert_pastebin" in option:
        pastebin_re = re.compile(r'pastebin.com/(\w+)', re.I)
        pastebin_m = pastebin_re.search(url)
        if pastebin_m:
            #weechat.prnt(urlsave_buffer, match.group(1))
            return "pastebin.com/raw.php?i=%s" % pastebin_m.group(1)

    # if imgur
    #http://imgur.com/download/40m3bjJ
    #http://imgur.com/40m3bjJ
    if "convert_imgur" in option:
        imgur_re = re.compile(r'imgur.com/(?:gallery/|)(\w+)', re.I)
        imgur_m = imgur_re.search(url)
        if imgur_m:
            return "imgur.com/download/%s" % imgur_m.group(1)

    # if youtube 
    # TBD

def urlsave_print_cb(data, buffer, date, tags, displayed, highlight, prefix, message):
    """ Called when a message is printed. """
    global urlsave_buffer, urlsave_tags

    # Exit immediately if the buffer does not exist
    if not urlsave_buffer:
        return weechat.WEECHAT_RC_OK

    # Exit if the wanted tag is not in the message
    tagslist = tags.split(",")
    if not "notify_message" in tagslist:
        if weechat.config_get_plugin("display_private") == "on":
            if not "notify_private" in tagslist:
                return weechat.WEECHAT_RC_OK
        else:
            return weechat.WEECHAT_RC_OK

    # Exit if the message came from a buffer that is not on the include channels
    no_skips = weechat.config_get_plugin("include_channels")
    if no_skips != "on":
        buffer_channel = str(weechat.buffer_get_string(buffer, "name"))
        include_channels = set(weechat.config_get_plugin("include_channels").split(","))

        if buffer_channel not in include_channels:
            return weechat.WEECHAT_RC_OK

    # Process all URLs from the message
    for url in url_re.findall(message):
        output = ""

        if weechat.config_get_plugin("skip_duplicates") == "on":
            if is_url_listed(urlsave_buffer, url):
                continue

        #date_str = datetime.fromtimestamp(int(date)).strftime('%Y-%m-%d %H:%M:%S')
        # hash
        hashstr = os.urandom(8).encode('hex')
        output += "%s%s %s " % (weechat.color("reset"), hashstr, buffer_channel)

        if weechat.config_get_plugin("display_nick") == "on":
            output += "%s " % (prefix)

        # Output the formatted URL into the buffer
        weechat.prnt(urlsave_buffer, output + url)

        # post print actions

        # convert URL
        convert_option = [ x for x in urlsave_settings.keys() if 'convert_' in x ]

        url = convert_url(url, convert_option)

        # run the hooked command
        hook_command = weechat.config_get_plugin("hook_command")
        folder = weechat.config_get_plugin("save_folder")
        output_file = os.path.join(folder, buffer_channel, hashstr)
        command = hook_command % (url, output_file)
        #weechat.prnt(urlsave_buffer, command)
        weechat.hook_process(command, 60000, "urlsave_hook_cb", "")

    return weechat.WEECHAT_RC_OK


def urlsave_hook_cb(data, command, code, out, err):
    """ A Dummy callback for hook command. """
    return weechat.WEECHAT_RC_OK


def urlsave_input_cb(data, buffer, input_data):
    """ A Dummy callback for buffer input. """
    return weechat.WEECHAT_RC_OK


def urlsave_close_cb(data, buffer):
    """ A callback for buffer closing. """
    global urlsave_buffer

    urlsave_buffer = None
    return weechat.WEECHAT_RC_OK


if __name__ == "__main__" and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
        version = weechat.info_get('version_number', '') or 0

        # Set default settings
        for option, default_value in urlsave_settings.iteritems():
            if not weechat.config_is_set_plugin(option):
                weechat.config_set_plugin(option, default_value[0])
            if int(version) >= 0x00030500:
                weechat.config_set_desc_plugin(option, default_value[1])

        urlsave_buffer = weechat.buffer_search("python", "urlsave")

        if not urlsave_buffer:
            # Create urlsave. Sets notify to 0 as this buffer does not need to
            # be in hotlist.
            urlsave_buffer = weechat.buffer_new("urlsave", "urlsave_input_cb", \
                    "", "urlsave_close_cb", "")
            weechat.buffer_set(urlsave_buffer, "title", "URL buffer")
            weechat.buffer_set(urlsave_buffer, "notify", "0")
            weechat.buffer_set(urlsave_buffer, "nicklist", "0")

        # Hook all public and private messages (some may think this is too limiting)
        weechat.hook_print("", "notify_message", "", 1, "urlsave_print_cb", "")
        weechat.hook_print("", "notify_private", "", 1, "urlsave_print_cb", "")
