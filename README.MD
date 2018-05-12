# Mifare clasic dump safe converter
A python script to convert **Mifare classic 1k cards** data dumps into safe dumps avoiding **brick** the new cards.

## Getting Started
These instructions will get you a copy of the project up and running on your environment.

- **CARE!!!** This script only check the access conditions for trailer blocks, any issue with access data conditions will be not evaluated.

#### How it works
The scripts read all the access conditions for each sector and modify those to the best similar conditions avoiding brick the cards.

For this, it map each case to the best case like this:
```python
# Each possible case
MCTYPES = {
	"000": "transport",
	"001": "transport",
	"010": "transport",
	"011": "default",
	"100": "default",
	"101": "minimal",
	"110": "default",
	"111": "default"
}
# Types that are secure 
SCTYPES = {
	"transport": [False, False, True], #001
	"default": [False, True, True], #011
	"minimal": [True, False, True] #101
}
```

Anyway, you can force to any secure type using command arguments.

### Prerequisites
For run this project you need:
 - [Python](https://www.python.org/) - Python release

### Setup
When you are done with prerequisites, you only need to clone this git repo.

```bash
## Note that script is invoked using source
git clone https://github.com/Xustyx/mfdsafe.git
```

Another way is download it manually following those steps that maybe you don't need to do:
```bash
## Note that script is invoked using source
wget https://github.com/Xustyx/mfdsafe/archive/master.zip
unzip master.zip
```
If you want, you can copy the script to your bin directory.

### Run
Once you completed, you can be able to run `./mfdsafe.py` inside the project folder or `mfdsafe` if you copied it to bin directory. 

#### Arguments
As you can see, if you run the script without parameters a help banner with all arguments appears.
```bash
./mfdsafe.py 
usage: mfdsafe.py [-h] -o OUTPUT [-t {transport,default}] [-v] input
mfdsafe.py: error: too few arguments
```
The arguments are the next:

- (required) **INPUT**: The input dump file to read.
- (required) **-o OUTPUT**: The output file to write the new safe dump.
- (optional) **[-t] {transport,default}**: Force all trailer access bits to **transport** (001) or **default** (011).
- (optional) **[-v]**: More verbose output.
- (optional) **[-h]**: Shows the help banner.


#### Examples

```bash
# Create a new dump file called safe-mydump.mfd mapping the actual access bits to the most similar safe conditions.
./mfdread mydump.mfd -o safe-mydump.mfd
```
```bash
# Create a new dump file called safe-mydump.mfd with all trailer access bits to transport (001) with debug info.
./mfdread mydump.mfd -o safe-mydump.mfd -t transport -v
```

## TODO
- [ ]  Use direct byte conversion without codecs.
- [ ]  Allow Mifare classic 4k dumps.

## Acknowledgments
* **zhovner** (mfdread) https://github.com/zhovner/mfdread


## Disclaimer
The author can not be held liable for any use of this code.
