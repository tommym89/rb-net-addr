#!/usr/bin/ruby
#
require 'set'
class RbNetAddr

  attr_reader :address
  attr_reader :mask
  attr_reader :cidr_mask
  attr_reader :network
  attr_reader :broadcast

  # regex to check if a string is an IP address
  @@ip_re = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/

  # valid subnet mask octet values
  @@mask_values = [0, 128, 192, 224, 240, 248, 252, 254, 255]

  # we can create a new RbNetAddr object with an address and full subnet mask, or just an address in the form "address/cidr_mask"
  def initialize(address, mask=nil)
    raise "Invalid address or subnet mask!" if not set_new(address, mask)
  end

  # public is implicit, we're declaring here only for clarity for developers
  public

  # class method to check if two networks overlap
  def RbNetAddr.within(network1, network2)
    return false if (! network1.instance_of?(RbNetAddr) || ! network2.instance_of?(RbNetAddr))
    return true if network1.network == network2.network
    mask1_total = RbNetAddr.total_mask(network1.mask)
    mask2_total = RbNetAddr.total_mask(network2.mask)
    if mask1_total < mask2_total
      netaddr3 = RbNetAddr.new(network2.network, network1.mask)
      return true if network1.network == netaddr3.network
    elsif mask2_total < mask1_total
      netaddr3 = RbNetAddr.new(network1.network, network2.mask)
      return true if network2.network == netaddr3.network
    end
    return false
  end

  # class method that accepts an array of RbNetAddr objects and returns a summarized array; i.e. if input is [RbNetAddr.new("192.168.56.0/24"), RbNetAddr.new("192.168.0.0/16")] the returned array will be [RbNetAddr.new("192.168.0.0/16")]
  def RbNetAddr.summarize(subnets)
    # remove any array members that are not RbNetAddr objects
    subnets.each do |sn|
      if ! sn.instance_of? RbNetAddr
        subnets.delete(sn)
      end
    end
    return nil if subnets.length == 0
    sorted_nets = subnets.sort_by(&:cidr_mask)
    summarized = Set.new
    while sorted_nets.length > 0
      tmp_net = sorted_nets.pop
      found = false
      sorted_nets.each do |sn|
        if RbNetAddr.within(tmp_net, sn)
          summarized.add?(sn)
          found = true
          break
        end
      end
      if ! found
        summarized.add?(tmp_net)
      end
    end
    # sort by cidr mask, if equal tiebreaker is network
    return summarized.sort { |sn1,sn2| (sn1.cidr_mask <=> sn2.cidr_mask) == 0 ? sn1.network <=> sn2.network : sn1.cidr_mask <=> sn2.cidr_mask }
  end

  private

  # return the sum of all mask octets
  def RbNetAddr.total_mask(mask)
    total = 0
    mask.split(".").each do |x|
      total += x.to_i
    end
    return total
  end

  # called by initialize to build RbNetAddr object
  def set_new(address, mask)
    if is_valid_addr(address.split("/")[0])
      @address = address.split("/")[0]
    else
      puts "Error, invalid IP address!"
      return false
    end
    if mask == nil
      calc_full_mask(address.split("/")[1].to_i)
      mask = @mask
    end
    if is_valid_mask(mask)
      @mask = mask
    else
      puts "Error, invalid subnet mask!"
      return false
    end
    calc_network
    calc_broadcast
    return true
  end

  # check if address is a valid IP address
  def is_valid_addr(address)
    if address =~ @@ip_re
      splitter = address.split(".")
      for i in 0...splitter.length do
        tmp_i = splitter[i].to_i
        return false if i == 0 && tmp_i == 0
        return false if tmp_i < 0 || tmp_i > 255
      end
      return true
    end
    return false
  end

  # check if mask is a valid mask
  def is_valid_mask(mask)
    if mask =~ @@ip_re
      splitter = mask.split(".")
      for i in 0...splitter.length do
        tmp_i = splitter[i].to_i
        return false if ! @@mask_values.include? tmp_i
        # check for next octet as <= current
        return false if i > 0 && tmp_i > splitter[i-1].to_i
      end
      calc_cidr_mask(mask)
      return true
    end
    return false
  end

  # calculate and set network value from address and mask
  def calc_network
    addr_splitter = @address.split(".")
    mask_splitter = @mask.split(".")
    network_arr = []
    for i in 0...addr_splitter.length do
      network_arr << (addr_splitter[i].to_i & mask_splitter[i].to_i).to_s
    end
    @network = network_arr.join(".")
  end

  # calculate and set broadcast value from network and mask
  def calc_broadcast
    network_splitter = @network.split(".")
    mask_splitter = @mask.split(".")
    i = mask_splitter.length - 1
    breaker = false
    while i >= 0 && ! breaker
      network_octet = network_splitter[i].to_i.to_s(2).rjust(8, "0")
      mask_octet = mask_splitter[i].to_i.to_s(2).rjust(8, "0")
      j = mask_octet.length - 1
      tmp_octet = network_octet.split("")
      while j >= 0
        if mask_octet[j] == "0"
          tmp_octet[j] = "1"
        else
          breaker = true
          break
        end
        j -= 1
      end
      network_splitter[i] = tmp_octet.join("").to_i(2).to_s
      i -= 1
    end
    @broadcast = network_splitter.join(".")
  end

  # calculate and set cidr mask value from full subnet mask
  def calc_cidr_mask(mask)
    mask_splitter = mask.split(".")
    @cidr_mask = 0
    mask_splitter.each do |octet|
      @cidr_mask += octet.to_i.to_s(2).count("1")
    end
  end

  # calculate and set full subnet mask value from cidr mask
  def calc_full_mask(cidr_mask)
    cidr_bits = "1"*cidr_mask + "0"*(32-cidr_mask)
    cidr_bits_arr = [ 
      cidr_bits[0...8].to_i(2).to_s, 
      cidr_bits[8...16].to_i(2).to_s,
      cidr_bits[16...24].to_i(2).to_s,
      cidr_bits[24...32].to_i(2).to_s
    ]
    @mask = cidr_bits_arr.join(".")
  end
end

# examples below
=begin
print_netaddr = Proc.new { |netaddr| puts "Created netaddr object with address #{netaddr.address}, mask #{netaddr.mask}, network #{netaddr.network}/#{netaddr.cidr_mask}, broadcast #{netaddr.broadcast}" }

netaddr1 = RbNetAddr.new("192.168.56.10", "255.255.255.192")
netaddr2 = RbNetAddr.new("192.168.0.0", "255.255.128.0")
netaddr3 = RbNetAddr.new("8.8.8.8", "255.255.240.0")
netaddr4 = RbNetAddr.new("8.8.4.4", "255.255.0.0")
netaddr5 = RbNetAddr.new("8.7.8.1", "255.255.255.0")
netaddr6 = RbNetAddr.new("8.9.8.1", "255.255.255.128")
netaddr7 = RbNetAddr.new("8.6.8.1", "255.255.255.128")
netaddr8 = RbNetAddr.new("172.31.21.5/20")

within = RbNetAddr.within(netaddr1, netaddr2)
puts within ? "#{netaddr1.network}/#{netaddr1.cidr_mask} and #{netaddr2.network}/#{netaddr2.cidr_mask} overlap." : "#{netaddr1.network}/#{netaddr1.cidr_mask} and #{netaddr2.network}/#{netaddr2.cidr_mask} do not overlap."

summarized = RbNetAddr.summarize([netaddr1, netaddr2, netaddr3, netaddr4, netaddr5, netaddr6, netaddr7, netaddr8])
summarized.each do |sn|
  print_netaddr.call(sn)
end
=end
