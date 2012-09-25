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

require 'time'

require './lib/snort_log_parser'
require './lib/openpaths_location_parser'
require './lib/last_parser'

class Analyser
  def initialize
    @snort_parser = SnortLogParser.new
    @openpaths_parser = OpenpathsLocationParser.new
    @last_parser = LastParser.new
  end

  # Find a location for the specified pair
  def match_location(snort_pair, locations)
    desired_time = snort_pair[0].time

    previous_location = nil
    #assumes locations are in chronological order
    for location in locations
      #If we have an exact match then just return the location for that time
      return location if location.time == desired_time

      if location.time > desired_time
        #find the closest out of the current and previous location
        previous_diff = desired_time - previous_location.time
        current_diff = location.time - desired_time
        if previous_diff <= current_diff
          return previous_location
        else
          return location
        end
      end
      previous_location = location
    end
    return previous_location
  end

  def match_logins logins, ip, time
      logins.select {|l| l.ip == ip and l.login_time <= time and l.logout_time >= time }
  end

  def get_user_ips logins
      logins.collect {|l| l.ip }.uniq
  end

  def extract_host text
      # Try to match a HTTP hostname header
      if m = /^Host: ?(?<host>.*)\n/.match(text)
          m[:host]
      else
          nil
      end
  end

  def analyse(snortfile, openpathsfile, last_file)
    logins = @last_parser.parse(last_file)
    snort_pairs = @snort_parser.analyse(snortfile, get_user_ips(logins))
    locations = @openpaths_parser.parse(openpathsfile)

    for pair in snort_pairs
      location = match_location(pair, locations)
      unless location.nil?
        # p1 is the user client request, p2 is the VPN request
        p1, p2 = pair
        # Find users that were active at this time via the source IP
        users = match_logins(logins, p1.source_ip, p1.time)
                  .collect {|l| l.user }
                  .uniq
                  .join(',')
        host = extract_host p2.text
        host = "(unknown)" if host.nil?
        if p1.source_ip != p2.destination_ip
            puts "#{users} #{p1.time.utc.iso8601(0)} #{p1.source_ip} " \
                 "#{p2.destination_ip}:#{p2.destination_port} "        \
                 "#{location.latitude},#{location.longitude} #{host}"
        end
      end
    end
  end
end

# command line arguments
if ARGV.length < 3
  puts "Usage: ruby analyse.rb snort_input_file openpaths_json_file user_ip_address"
else
  snortfile = ARGV[0]
  openpathsfile = ARGV[1]
  user_ip = ARGV[2]
  analyser = Analyser.new
  analyser.analyse(snortfile, openpathsfile, user_ip)
end


