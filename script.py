from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from PIL import Image
import pefile
import magic
import hashlib
import os
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
from datetime import datetime
import string
import re

app = Flask(__name__)
CORS(app)

model = load_model('malware_model_checkpoints.h5.keras')

def calculate_hashes(file_path):
    """Calculate various hashes of the file."""
    with open(file_path, 'rb') as f:
        content = f.read()

    return {
        'md5': hashlib.md5(content).hexdigest(),
        'sha1': hashlib.sha1(content).hexdigest(),
        'sha256': hashlib.sha256(content).hexdigest(),
        'ssdeep': "Some Random ssdeep data"
    }


def extract_strings(file_path, min_length=4):
    """Extract ASCII and Unicode strings from the file."""
    with open(file_path, 'rb') as f:
        content = f.read()

    ascii_strings = re.findall(b'[%s]{%d,}' % (string.printable.encode(), min_length), content)
    ascii_strings = [s.decode(errors='ignore') for s in ascii_strings]

    # Unicode strings
    unicode_strings = re.findall(b'(?:[\x20-\x7E][\x00]){%d,}' % min_length, content)
    unicode_strings = [s.decode('utf-16le', errors='ignore') for s in unicode_strings]

    return {
        'ascii_strings': ascii_strings,
        'unicode_strings': unicode_strings
    }


def analyze_pe(file_path):
    """Analyze PE file structure."""
    with pefile.PE(file_path) as pe:
        analysis = {
            'machine_type': hex(pe.FILE_HEADER.Machine),
            'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
            'subsystem': hex(pe.OPTIONAL_HEADER.Subsystem),
            'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        }

        # Extract imports
        imports = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports[entry.dll.decode()] = [
                func.name.decode() if func.name else str(func.ordinal)
                for func in entry.imports
            ]
        analysis['imports'] = imports

        # Extract sections
        sections = []
        for section in pe.sections:
            sections.append({
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData),
                'characteristics': hex(section.Characteristics)
            })
        analysis['sections'] = sections

    return analysis

    import os


def hex2img(array, output_img_path):
    if array.shape[1] != 16:  
        raise ValueError(f"Expected array shape to have 2nd dimension of size 16, but got {array.shape[1]}")

    b = int((array.shape[0] * 16) ** (0.5))
    b = 2 ** (int(np.log2(b)) + 1)
    a = int(array.shape[0] * 16 / b)
    print(a, b, array.shape)

    array = array[:a * b // 16, :]
    array = np.reshape(array, (a, b))

    im = Image.fromarray(np.uint8(array))

    im = im.resize((224, 224), Image.LANCZOS)

    im.save(output_img_path, "PNG")
    return im

unzipped_malwares_path = r'unzipped_malwares'
malware_image_path = r'malware_Image'

os.makedirs(malware_image_path, exist_ok=True)

binary_extensions = [
    '.exe', '.dll', '.macho', '.hta', '.wsf', '.apk', '.msi', '.bat', '.cmd',
    '.xlam', '.arj', '.r00', '.ppam', '.7z', '.zip', '.html', '.xls', '.xz',
    '.r07', '.gz', '.sh', '.pdf', '.lnk', '.a', '.docx', '.jar', '.com', '.z',
    '.php', '.img', '.r09', '.iso', '.unknown', '.js', '.xlsm', '.rtf', '.elf',
    '.xlsx', '.bin', '.rar', '.docm', '.ps1', '.vbs', '.doc', '.class'
]


def convert_to_image(file_path):
    print(f'Processing binary file: {file_path}')
    with open(file_path, 'rb') as f:
        file_data = bytearray(f.read())

    hex_array = []
    for count, byte in enumerate(file_data):
        hex_value = f'{byte:02x}' 
        hex_array.append(hex_value)

    array = []
    for i in range(0, len(hex_array), 16):
        if i + 16 <= len(hex_array):  # Ensure there are enough elements
            row = [int(hex_array[j], 16) for j in range(i, i + 16)]
            array.append(row)

    if not array:
        print(f"No valid hex data for file: {file_path}")
        return

    return np.array(array)


@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename.endswith('.exe'):
        return jsonify({'error': 'Invalid file type'}), 400

    # Save file temporarily
    temp_path = 'temp_file.exe'
    file.save(temp_path)

    try:
        # Basic file info
        file_info = {
            'file_name': file.filename,
            'file_size': os.path.getsize(temp_path),
            'file_type': magic.from_file(temp_path),
            'mime_type': magic.from_file(temp_path, mime=True)
        }

        # Calculate hashes
        hashes = calculate_hashes(temp_path)

        # Extract strings
        strings = extract_strings(temp_path)

        # Analyze PE structure
        pe_analysis = analyze_pe(temp_path)

        # Combine all results
        results = {
            'file_info': file_info,
            'hashes': hashes,
            'strings': strings,
            'pe_analysis': pe_analysis
        }

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route('/analyse_ai', methods=['POST'])
def analyse_with_ai():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename.endswith('.exe'):
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Save file temporarily
    temp_path = 'temp_file.exe'
    file.save(temp_path)
    
    try:
        file_info = {
            'file_name': file.filename,
            'file_size': os.path.getsize(temp_path),
            'file_type': magic.from_file(temp_path),
            'mime_type': magic.from_file(temp_path, mime=True)
        }
        
        img_array = convert_to_image(temp_path)
        
        img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension
        img_array = img_array / 255.0 
        
        predictions = model.predict(img_array)
        predicted_class = np.argmax(predictions, axis=1)
        
        hashes = calculate_hashes(temp_path)
        pe_analysis = analyze_pe(temp_path)
    
        
        print(predicted_class)
        
        results = {
            'file_info': file_info,
            'hashes': hashes,
            'strings': predicted_class,
            'pe_analysis': pe_analysis
        }
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Clean up
        if os.path.exists(temp_path):
            os.remove(temp_path)
    

if __name__ == '__main__':
    app.run(debug=True)

