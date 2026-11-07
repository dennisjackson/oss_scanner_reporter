# oss_scanner_reporter

`file_bmo_bug.py` files the findings of an OSS-scanner scan as security bugs on
[Bugzilla](https://bugzilla.mozilla.org). Every finding becomes a bug in the
product's default restricted access security group, with the report and its patches and reproducer
attached. All of the bugs block one meta bug for the scan.

## Usage

File a meta bug for OSS-Scanner in your component if you don't already have one. 

```sh
./file_bmo_bug.py --meta-bug <overall meta bug> <scan directory>
```

The tool will then file a bug blocking the meta bug for this batch of scan results and then 
file individual scan results as individual bugs blocking the scan bug.  

The bugs are filed in the product and component of `--meta-bug`. 

It is safe to run again: findings that already have a bug are not filed twice,
and anything a run failed to do is retried. Each run is recorded in
`bmo-filing.log` in the scan directory, which the script also uses to avoid
filing duplicates. 

Don't run two copies at once for the same scan. Ensure no one else runs this tool
for same batch of scan results at the same time. 

Run `./file_bmo_bug.py --help` for the details.
