import struct
from zipfile import ZipFile
from time import sleep
import os
import re

# TYPE=['Adware','Banking','Benign','SMS']
TYPE = ['Benign']
PATH = r"C:\Users\teebow1e\Downloads\sampleapk"
DESTINATION_PATH = r"C:\Users\teebow1e\Downloads\sampleapk\processed"

def padded(i):
    if i < 10:
        return f'000{i}'
    if i < 100:
        return f'00{i}'
    if i < 1000:
        return f'0{i}'
    return str(i)

def check_zip_signature(file_path):
    """Check if a file starts with the ZIP signature (50 4B 03 04)"""
    try:
        with open(file_path, 'rb') as f:
            # Read the first 4 bytes
            magic_bytes = f.read(4)
            # ZIP/APK signature is 50 4B 03 04 in hex, which is b'PK\x03\x04' in bytes
            return magic_bytes == b'PK\x03\x04'
    except Exception as e:
        print(f"Error checking file signature: {e}")
        return False

def get_apk_list(category):
    try:
        category_path = os.path.join(PATH, category)
        print(category_path)
        all_files = os.listdir(category_path)

        # Check all files for ZIP signature, not just .apk files
        apk_files = []
        non_apk_files = []

        for filename in all_files:
            file_path = os.path.join(category_path, filename)
            if os.path.isfile(file_path):
                if check_zip_signature(file_path):
                    apk_files.append(filename)
                    if not filename.endswith('.apk'):
                        print(f"Found APK with non-standard extension: {filename}")
                else:
                    non_apk_files.append(filename)

        print(f"Found {len(apk_files)} valid APK files and {len(non_apk_files)} non-APK files")
        if non_apk_files:
            print(f"Non-APK files: {non_apk_files}")

        return apk_files
    except Exception as e:
        print(f"Error getting APK list for {category}: {e}")
        return []

def get_highest_folder_id(category):
    """Get the highest folder ID number for the given category"""
    try:
        category_path = os.path.join(DESTINATION_PATH, category)
        if not os.path.exists(category_path):
            return 599  # Return 599 so next ID will be 600

        all_folders = os.listdir(category_path)
        if not all_folders:
            return 599  # Return 599 so next ID will be 600

        highest_id = 599  # Default to 599 so next ID will be 600
        pattern = re.compile(fr"{category}_(\d+)")

        for folder_name in all_folders:
            match = pattern.match(folder_name)
            if match:
                try:
                    folder_id = int(match.group(1))
                    if folder_id > highest_id:
                        highest_id = folder_id
                except ValueError:
                    continue

        return highest_id
    except Exception as e:
        print(f"Error getting highest folder ID: {e}")
        return 599  # Return 599 so next ID will be 600

def create_directory(category, id):
    try:
        dir_path = os.path.join(DESTINATION_PATH, category, f"{category}_{id}")
        # Use makedirs to create nested directories
        os.makedirs(dir_path, exist_ok=True)
        return 1
    except Exception as e:
        print(f"Error creating directory: {e}")
        return -1

##################################
#       APK_PROCESSING_FUNCTION  #
##################################

def unzipping_apk(id, category, apk_file_name):
    try:
        # Create directory first
        if create_directory(category, id) == -1:
            return Exception("Failed to create directory")

        apk_path = os.path.join(PATH, category, apk_file_name)
        dest_path = os.path.join(DESTINATION_PATH, category, f"{category}_{id}")

        with ZipFile(apk_path, "r") as apk:
            apk.extract("classes.dex", path=dest_path)

        return os.path.join(dest_path, "classes.dex")
    except Exception as e:
        return e

def padding(file_path, target_size=1536000):
    try:
        with open(file_path, "ab") as f:
            current_size = f.tell()  # Get the current file size

            if current_size < target_size:
                padding_size = target_size - current_size
                f.write(b'\x00' * padding_size)
    except Exception as e:
        print(f"Error padding file: {e}")

def extract_data_section(dex_file_path, output_file_path):
    try:
        with open(dex_file_path, 'rb') as f:
            # Read the header (the first 0x70 bytes)
            header = f.read(0x70)

            # Unpack relevant fields from the header (little-endian format)
            # Referencing the DEX file format:
            #   - data_off (0x6C): Offset of the data section
            #   - data_size (0x68): Size of the data section
            data_size, data_off = struct.unpack_from('<II', header, 0x68)

            print(f"Data section offset: {data_off}")
            print(f"Data section size: {data_size}")

            # Seek to the data section
            f.seek(data_off)

            # Read the data section
            data_section = f.read(min(data_size, 1500*1024))

        # Save the extracted data section to a file
        with open(output_file_path, 'wb') as out_file:
            out_file.write(data_section)

        print(f"Data section extracted to: {output_file_path}")

        # Remove the original DEX file
        os.remove(dex_file_path)

        return data_size
    except Exception as e:
        print(f"Error extracting data section: {e}")
        return -1

if __name__ == "__main__":
    ERROR_IDS = {
        'Adware': [],
        'Benign': [],
        'Banking': [],
        'SMS': []
    }

    # Ensure base directory structure exists
    print("Creating base directory structure...")
    for category in TYPE:
        category_path = os.path.join(DESTINATION_PATH, category)
        os.makedirs(category_path, exist_ok=True)

    for category in TYPE:
        list_apk = get_apk_list(category)
        print(f"\nProcessing {len(list_apk)} APK files in {category}")
        print(list_apk)

        # Get the highest existing folder ID
        highest_id = get_highest_folder_id(category)
        start_id = highest_id + 1
        print(f"Highest existing folder ID: {highest_id}")
        print(f"Starting from ID: {start_id}")

        # Process each APK file with a new, incremented ID
        current_id = start_id
        for apk_file in list_apk:
            try:
                print(f"\n--- Processing file with ID {current_id}: {apk_file} ---")

                dex_path = unzipping_apk(padded(current_id), category, apk_file)
                dest_path = os.path.join(DESTINATION_PATH, category,
                                       f"{category}_{padded(current_id)}", "data_section.bin")

                if isinstance(dex_path, Exception):
                    ERROR_IDS[category].append(current_id)
                    print(f"Error: {dex_path}")
                    print(f"Failed to extract file {apk_file}")
                else:
                    print(f"Successfully extracted classes.dex: {dex_path}")
                    extractor = extract_data_section(dex_path, dest_path)

                    if extractor == -1:
                        ERROR_IDS[category].append(current_id)
                        print(f"Failed to extract data section for {apk_file}")
                    else:
                        padding(file_path=dest_path)
                        print(f"Successfully processed {apk_file}")

                # Increment ID for next file
                current_id += 1

            except Exception as e:
                print(f"Unexpected error processing {category} file {apk_file}: {e}")
                ERROR_IDS[category].append(current_id)
                current_id += 1

    # Print summary
    print("\n=== Processing Summary ===")
    for category in TYPE:
        print(f"{category} error ids: {ERROR_IDS[category]}")
        print(f"Total errors for {category}: {len(ERROR_IDS[category])}")
