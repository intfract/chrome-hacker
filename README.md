# Chrome Hacker

Chrome Password Grabber for Windows
> This repository was made for educational purposes only!

## Usage

### Install Dependencies

```sh
pip install pywin32
pip install pycryptodomex
```

### Run Python File

Make sure you are in the same directory as your python file before you run this command.

```sh
python main.py
```

### Output

A `details.csv` file will be generated in your current directory with a table of all URLs, usernames, and passwords.

If `SHOULD_POST` is set to true, then the program will also post all the data to your `API_ENDPOINT` of choice.

## Credits

This project was based off the [Decrypt Chrome Passwords repository](https://github.com/ohyicong/decrypt-chrome-passwords/).
