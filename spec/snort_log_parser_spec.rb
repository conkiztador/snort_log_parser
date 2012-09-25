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

require 'snort_log_parser'

describe SnortLogParser do

  #it "should work for large test data" do
  #  logParser = SnortLogParser.new
  #  pairs = logParser.analyse("large_test_data.log", ["1.151.79.26", "128.250.152.198"])
  #  pairs.should_not == nil
  #end

  it "should parse test data for 20120515 11:29am" do
    logParser = SnortLogParser.new
    pairs = logParser.analyse("traffic_data/log_20120515/snort.log.1337044274.txt", ["1.139.177.134"])
    pairs.should_not == nil
  end

  describe "parse a single entry" do
  
    before(:each) do
      @test_data_1 = %Q{05/11-05:36:02.774215 123.30.174.116:80 -> 115.146.93.245:57964
TCP TTL:107 TOS:0x0 ID:26770 IpLen:20 DgmLen:40 DF
***A*R** Seq: 0x0  Ack: 0x3C74EF5E  Win: 0x0  TcpLen: 20}

      @test_data_2 = %Q{05/11-05:36:03.623624 1.151.79.26 -> 115.146.94.29
GRE TTL:239 TOS:0x0 ID:20193 IpLen:20 DgmLen:808}

      @logParser = SnortLogParser.new
    end

    it "handles invalid data" do
      lambda {@logParser.parse_entry("abcd")}.should raise_error
    end

    describe "from test_data_1" do
      before(:each) do
        @entry = @logParser.parse_entry(@test_data_1)
      end

      it "gets source IP" do
        @entry.source_ip.should == "123.30.174.116"
        @entry.source_port.should == "80"
      end

      it "gets destination IP" do
        @entry.destination_ip.should == "115.146.93.245"
        @entry.destination_port.should == "57964"
      end

      it "gets datagram length" do
        @entry.datagram_length.should == 40
      end

      it "get the time" do
        @entry.time.should be_within(1).of Time.utc(2012, 5, 11, 5, 36, 02)
      end
    end

    describe "from test_data_2" do
      before(:each) do
        @entry = @logParser.parse_entry(@test_data_2)
      end

      it "gets source IP" do
        @entry.source_ip.should == "1.151.79.26"
        @entry.source_port.should == nil
      end

      it "gets destination IP" do
        @entry.destination_ip.should == "115.146.94.29"
        @entry.destination_port == nil
      end

      it "gets datagram length" do
        @entry.datagram_length.should == 808
      end
    end
  end

  describe "parse time" do
    it "from example" do
      log_parser = SnortLogParser.new
      log_parser.parse_time("05/11", "05:34:58.614585").should be_within(1).of Time.utc(2012, 5, 11, 5, 34, 58)
    end
  end

  describe "parse multiple entries" do

    describe "from small test data" do
      before(:each) do
        @log_parser = SnortLogParser.new
        @filename = "test_data/small_test_data.log"
        @entries = @log_parser.parse_file(@filename)
      end

      it "should parse 3 entries" do
        @entries.length.should == 3
      end

      describe "the first entry" do
        before(:each) do
          @entry = @entries[0]
        end

        it "should have correct values" do
          @entry.source_ip.should == "128.250.152.217"
          @entry.source_port.should == "59444"
        end
      end

      describe "the second entry" do
        before(:each) do
          @entry = @entries[1]
        end

        it "should have a packet body" do
          @entry.packet.should_not == nil
        end
      end
    end

    describe "from large test data" do
      it "should parse the file" do
        log_parser = SnortLogParser.new
        filename = "test_data/large_test_data.log"
        entries = log_parser.parse_file(filename)
        entries.length.should == 5278
      end
    end

  end

end

describe Entry do
  before(:each) do
    #create an entry
    @entry = Entry.new
    @source_ip = "1.2.3.4"
    @entry.source_ip = @source_ip
  end

  it "should have correct source_ip" do
    @entry.source_ip.should == @source_ip
  end

  describe "using a hashmap" do
    it "should create an entry" do
      args = {
         :source_ip => "1.2.3.4", 
         :destination_ip => "2.3.4.5", 
         :datagram_length => 123, 
         :packet => "1234", 
         :time => Time.at(100), 
         :source_port => 80, 
         :destination_port => 81
      }
      entry = Entry.new(args)
      entry.source_ip.should == "1.2.3.4"
      entry.destination_ip.should == "2.3.4.5"
      entry.datagram_length.should == 123
      entry.packet.should == "1234"
      entry.time.should == Time.at(100)
      entry.source_port.should == 80
      entry.destination_port.should == 81
    end
  end
end
