# Copyright (c) 2012, VeRSI Consortium, Gregory Long
#   (Victorian eResearch Strategic Initiative, Australia)
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the VeRSI, the VeRSI Consortium members, nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'date'

class LastEntry
  attr_accessor :user, :ip, :login_time, :logout_time
end

"""
Sample last output:
stud000  ppp0         2.2.2.2          Tue Sep 18 05:14 - 05:19  (00:04)....
ubuntu   pts/0        3.3.3.3          Tue Sep 18 03:56   still logged in...

wtmp begins Fri Sep 14 06:41:20 2012
"""

class LastParser
  def parse filename
    last_output = File.read filename
    lines = last_output.split("\n")
    entries = []
    for line in lines[0..-3]
      e = LastEntry.new
      e.user, iface, e.ip, time = line.split(" ", 4)
      times = time.split(" - ")
      e.login_time = DateTime.strptime(times[0], "%a %b %d %H:%M")
      e.logout_time = File.mtime(filename).to_datetime
      if times.length == 2
        date_str = times[0][0..-6] + times[1][0..5]
        e.logout_time = DateTime.strptime(date_str, "%a %b %d %H:%M")
      end
      entries << e
    end
    entries
  end
end

