#!/usr/bin/env bash

################################################################################
# ALIASES
################################################################################

alias ext='extract'
alias fh='filehash'

################################################################################
# EXTRACT
################################################################################

extract() {
  OPTIND=1

  usage() {
    cbc_style_box "$CATPPUCCIN_MAUVE" "Description:" \
      "  Extract a variety of compressed archive formats."

    cbc_style_box "$CATPPUCCIN_BLUE" "Usage:" \
      "  extract [file] [-h]"

    cbc_style_box "$CATPPUCCIN_TEAL" "Options:" \
      "  -h    Display this help message"

    cbc_style_box "$CATPPUCCIN_PEACH" "Example:" \
      "  extract file.tar.gz"
  }

  while getopts ":h" opt; do
    case ${opt} in
    h)
      usage
      return 0
      ;;
    \?)
      cbc_style_message "$CATPPUCCIN_RED" "Invalid option: -$OPTARG"
      return 1
      ;;
    esac
  done

  shift $((OPTIND - 1))

  if [ -z "$1" ]; then
    cbc_style_message "$CATPPUCCIN_RED" "Error: No file specified"
    return 1
  fi

  if [ ! -f "$1" ]; then
    cbc_style_message "$CATPPUCCIN_RED" "Error: File not found"
    return 1
  fi

  case "$1" in
  *.tar.bz2) tar xjf "$1" ;;
  *.tar.gz) tar xzf "$1" ;;
  *.bz2) bunzip2 "$1" ;;
  *.rar) unrar x "$1" ;;
  *.gz) gunzip "$1" ;;
  *.tar) tar xf "$1" ;;
  *.tbz2) tar xjf "$1" ;;
  *.tgz) tar xzf "$1" ;;
  *.zip) unzip "$1" ;;
  *.Z) uncompress "$1" ;;
  *.7z) 7z x "$1" ;;
  *.deb) ar x "$1" ;;
  *.tar.xz) tar xf "$1" ;;
  *.tar.zst) unzstd "$1" ;;
  *) cbc_style_message "$CATPPUCCIN_RED" "'$1' cannot be extracted using extract()" ;;
  esac
}

################################################################################
# FILEHASH
################################################################################

filehash() {
  OPTIND=1
  OPTERR=0

  local default_method="sha256"

  usage() {
    cbc_style_box "$CATPPUCCIN_MAUVE" "Description:" \
      "  Generate hashes for files with various algorithms."

    cbc_style_box "$CATPPUCCIN_BLUE" "Usage:" \
      "  filehash [options] [file] [method]"

    cbc_style_box "$CATPPUCCIN_TEAL" "Options:" \
      "  -h        Display this help message" \
      "  -m        Display available hash methods" \
      "  -a        Run all hash methods on the file" \
      "  -d [meth] Run the method on each file in the current directory" \
      "  -da       Run all methods on every file in the current directory"

    cbc_style_box "$CATPPUCCIN_PEACH" "Examples:" \
      "  filehash report.pdf" \
      "  filehash report.pdf sha512" \
      "  filehash -d sha1"
  }

  list_methods() {
    cbc_style_box "$CATPPUCCIN_LAVENDER" "Available hash methods" \
      "  md5     – MD5 hash" \
      "  sha1    – SHA-1 hash" \
      "  sha224  – SHA-224 hash" \
      "  sha256  – SHA-256 hash" \
      "  sha384  – SHA-384 hash" \
      "  sha512  – SHA-512 hash" \
      "  blake2b – BLAKE2b hash"
  }

  method_command() {
    case "$1" in
    md5) printf 'md5sum' ;;
    sha1) printf 'sha1sum' ;;
    sha224) printf 'sha224sum' ;;
    sha256) printf 'sha256sum' ;;
    sha384) printf 'sha384sum' ;;
    sha512) printf 'sha512sum' ;;
    blake2b) printf 'b2sum' ;;
    *) return 1 ;;
    esac
  }

  method_title() {
    case "$1" in
    md5) printf 'MD5' ;;
    sha1) printf 'SHA-1' ;;
    sha224) printf 'SHA-224' ;;
    sha256) printf 'SHA-256' ;;
    sha384) printf 'SHA-384' ;;
    sha512) printf 'SHA-512' ;;
    blake2b) printf 'BLAKE2b' ;;
    *) return 1 ;;
    esac
  }

  validate_method() {
    if ! method_command "$1" >/dev/null 2>&1; then
      cbc_style_message "$CATPPUCCIN_RED" "Unsupported method: $1"
      return 1
    fi
  }

  print_hash_result() {
    local method="$1"
    local file="$2"
    local is_default="$3"

    local cmd
    cmd=$(method_command "$method") || return 1

    if [ ! -f "$file" ]; then
      cbc_style_message "$CATPPUCCIN_RED" "File not found: $file"
      return 1
    fi

    local hash_output
    if ! hash_output=$("$cmd" "$file"); then
      cbc_style_message "$CATPPUCCIN_RED" "Failed to calculate hash with $method for $file"
      return 1
    fi

    local hash_value=${hash_output%% *}
    local method_label
    method_label=$(method_title "$method") || return 1

    local method_line="  Method: $method_label"
    if [ "$is_default" = "1" ]; then
      method_line+=" (default)"
    fi

    cbc_style_box "$CATPPUCCIN_GREEN" "$method_label hash" \
      "  File: $file" \
      "$method_line" \
      "  Hash: $hash_value"
  }

  local opt
  local show_methods=0
  while getopts ":hm" opt; do
    case "$opt" in
    h)
      usage
      return 0
      ;;
    m)
      show_methods=1
      ;;
    \?)
      case "$OPTARG" in
      a | d)
        if [ "$OPTIND" -gt 1 ]; then
          OPTIND=$((OPTIND - 1))
        fi
        break
        ;;
      *)
        cbc_style_message "$CATPPUCCIN_RED" "Invalid option: -$OPTARG"
        usage
        return 1
        ;;
      esac
      ;;
    esac
  done

  shift $((OPTIND - 1))

  if [ "$show_methods" -eq 1 ]; then
    list_methods
    [ $# -eq 0 ] && return 0
  fi

  case "$1" in
  -a)
    shift
    if [ $# -eq 0 ]; then
      cbc_style_message "$CATPPUCCIN_RED" "File was not provided."
      usage
      return 1
    fi
    local file="$1"
    shift
    cbc_style_note "All methods" "  Running every hash on: $file"
    local method
    for method in md5 sha1 sha224 sha256 sha384 sha512 blake2b; do
      print_hash_result "$method" "$file" 0
    done
    return 0
    ;;
  -da)
    shift
    cbc_style_note "Directory scan" "  Running every method on regular files in: $(pwd)"
    local found=0
    local file
    for file in *; do
      if [ -f "$file" ]; then
        found=1
        cbc_style_box "$CATPPUCCIN_BLUE" "File: $file" "  All available hash methods"
        local method
        for method in md5 sha1 sha224 sha256 sha384 sha512 blake2b; do
          print_hash_result "$method" "$file" 0
        done
      fi
    done
    if [ "$found" -eq 0 ]; then
      cbc_style_message "$CATPPUCCIN_YELLOW" "No regular files found in $(pwd)."
    fi
    return 0
    ;;
  -d)
    shift
    local provided_method="$1"
    local used_default=0
    if [ -z "$provided_method" ]; then
      provided_method="$default_method"
      used_default=1
    else
      shift
    fi
    validate_method "$provided_method" || return 1
    local method_label
    method_label=$(method_title "$provided_method") || return 1
    local note_message="  Running $method_label on regular files in: $(pwd)"
    if [ "$used_default" -eq 1 ]; then
      note_message+=" (default)"
    fi
    cbc_style_note "Directory scan" "$note_message"
    local found=0
    local file
    for file in *; do
      if [ -f "$file" ]; then
        found=1
        print_hash_result "$provided_method" "$file" "$used_default"
      fi
    done
    if [ "$found" -eq 0 ]; then
      cbc_style_message "$CATPPUCCIN_YELLOW" "No regular files found in $(pwd)."
    fi
    return 0
    ;;
  esac

  if [ $# -eq 0 ]; then
    cbc_style_message "$CATPPUCCIN_RED" "File was not provided."
    usage
    return 1
  fi

  local file="$1"
  local method_arg="$2"
  local used_default=0
  if [ -z "$method_arg" ]; then
    method_arg="$default_method"
    used_default=1
  fi

  validate_method "$method_arg" || return 1
  print_hash_result "$method_arg" "$file" "$used_default"
}

################################################################################
# BACKUP
################################################################################

backup() {
  OPTIND=1

  local filename=$(basename "$1")                             # Get the base name of the file
  local timestamp=$(date +%Y.%m.%d.%H.%M.%S)                  # Get the current timestamp
  local backup_filename="${filename}_backup_${timestamp}.bak" # Create the backup file name

  usage() {
    cbc_style_box "$CATPPUCCIN_MAUVE" "Description:" \
      "  Create a timestamped backup of a specified file."

    cbc_style_box "$CATPPUCCIN_BLUE" "Usage:" \
      "  backup [file] [-h]"

    cbc_style_box "$CATPPUCCIN_TEAL" "Options:" \
      "  -h    Display this help message"

    cbc_style_box "$CATPPUCCIN_PEACH" "Example:" \
      "  backup test.txt"
  }

  while getopts ":h" opt; do
    case $opt in
    h)
      usage
      return
      ;;
    \?)
      cbc_style_message "$CATPPUCCIN_RED" "Invalid option: -$OPTARG. Use -h for help."
      return
      ;;
    esac
  done

  shift $((OPTIND - 1))

  # Function to check if no arguments are provided
  check_no_arguments() {
    if [ $# -eq 0 ]; then
      cbc_style_message "$CATPPUCCIN_RED" "Error: No arguments provided. Use -h for help."
      return 1
    fi
  }

  # Function to check if the file exists
  check_file_exists() {
    if [ ! -f "$1" ]; then
      cbc_style_message "$CATPPUCCIN_RED" "Error: File not found."
      return 1
    fi
  }

  # Function to create a backup file
  make_backup() {
    if cp "$1" "$backup_filename"; then
      cbc_style_message "$CATPPUCCIN_GREEN" "Backup created: $backup_filename"
    else
      cbc_style_message "$CATPPUCCIN_RED" "Failed to create backup."
      return 1
    fi
  }

  # Main logic
  main() {
    check_no_arguments "$@" || return
    check_file_exists "$1" || return
    make_backup "$1"
  }

  # Call the main function with arguments
  main "$@"
}
