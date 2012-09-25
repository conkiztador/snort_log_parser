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

require 'analyse'

describe Analyser do
  before (:each) do
    @analyser = Analyser.new
  end

  
  ## jwinton
  #it "should match snort log files with location data" do
  #  snortfile = "traffic_data/snort.log.1337067560.201205161033.txt"
  #  openpathsfile = "location_data/openpaths_jwinton.json"
  #  user_ip = "60.224.16.143"
  #  @analyser.analyse(snortfile, openpathsfile, user_ip)
  #end
  #
  ## jwinton
  #it "should match snort log files with location data" do
  #  snortfile = "traffic_data/snort.log.1337067560.201205161033.txt"
  #  openpathsfile = "location_data/openpaths_jwinton.json"
  #  user_ip = "49.176.33.46"
  #  @analyser.analyse(snortfile, openpathsfile, user_ip)
  #end


  
  # gdlong
  #it "should match snort log files with location data" do
  #  snortfile = "traffic_data/snort.log.1337067560.201205161033.txt"
  #  openpathsfile = "location_data/openpaths_gregorydavidlong.json"
  #  user_ip = "1.139.51.213"
  #  @analyser.analyse(snortfile, openpathsfile, user_ip)
  #end

  #it "should match snort log files with location data" do
  #  snortfile = "traffic_data/log_20120515/snort.log.1337044274.txt"
  #  openpathsfile = "location_data/openpaths_gregorydavidlong.json"
  #  user_ip = "1.139.177.134"
  #  @analyser.analyse(snortfile, openpathsfile, user_ip)
  #end

  describe "matching" do
    describe "a single data entry" do
      before(:each) do
        @location = LocationPoint.new 1, 1, "v1", Time.at(100000), "device", 1, "os"
      end

      it "should work for a single location" do
        time = Time.at(100000)
        @analyser.match_location(time, [@location]).should == @location
      end

      describe "for multiple locations" do
        before(:each) do
          @location2 =  LocationPoint.new 2, 2, "v1", Time.at(200000), "device", 2, "os"
          @locations = [ 
            @location,
            @location2,
            LocationPoint.new(3, 3, "v1", Time.at(300000), "device", 2, "os"),
          ]
        end

        it "with an exact match" do
          time = Time.at(100000)
          @analyser.match_location(time, @locations).should == @location
        end

        it "with an exact match in the middle" do
          time = Time.at(200000)
          @analyser.match_location(time, @locations).should == @location2
        end

        it "without an exact match, close to the subsequent location" do
          time = Time.at(190000)
          @analyser.match_location(time, @locations).should == @location2
        end

        it "without an exact match, close to the previous location" do
          time = Time.at(110000)
          @analyser.match_location(time, @locations).should == @location
        end
      end
    end

    describe "multple data entries" do
      it "should work for a single location"
      it "should work for multiple locations"
    end
  end

    describe "login matching" do
        before(:each) do
            @logins = [
                mock(:ip => '1.1.1.1', :login_time => Time.at(190199),
                     :logout_time => Time.at(190201)),
                mock(:ip => '1.1.1.1', :login_time => Time.at(190201),
                     :logout_time => Time.at(190202)),
                mock(:ip => '1.1.1.2', :login_time => Time.at(190199),
                     :logout_time => Time.at(190201)),
            ]
        end
        it "should match IP and current time to a user login session" do
            rv = @analyser.match_logins(@logins, '1.1.1.1', Time.at(190200))
            rv.should == @logins[0..0]
        end
        it "should match the correct IP" do
            rv = @analyser.match_logins(@logins, '1.1.1.2', Time.at(190200))
            rv.should == @logins[2..2]
        end
        it "should match times inclusively" do
            rv = @analyser.match_logins(@logins, '1.1.1.1', Time.at(190201))
            rv.should == @logins[0..1]
        end
        it "should return nothing if the IP isn't known" do
            rv = @analyser.match_logins(@logins, '1.1.1.3', Time.at(190200))
            rv.should == []
        end
        it "should return nothing if the time doesn't match" do
            rv = @analyser.match_logins(@logins, '1.1.1.1', Time.at(190205))
            rv.should == []
        end
  end
end
