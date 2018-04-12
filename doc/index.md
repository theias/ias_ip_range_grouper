# ias-ip-range-grouper

Please see the shell scripts located in test/.

Of particular interest might be:

* **run_watch_test.sh** - slowly send IP addresses into ias_ip_range_grouper.pl in watch mode

# Example output

In the test/ directory there's a list of IPs. 
<pre>
cat (list_of_ips) | ias_ip_range_grouper.pl
</pre>
to get a feel for how it works.
