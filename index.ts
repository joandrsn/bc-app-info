import * as fs from 'fs';
import * as yauzl from 'yauzl'
import * as xml2js from 'xml2js';

/**
 * Checks if the given file is a runtime package.
 * @param filename The filename to check
 * @returns A promise that resolves to true if the file is a runtime package, false otherwise.
 */
function isRuntimePackage(filename: fs.PathLike): Promise<boolean> {
  return new Promise<boolean>((resolve, reject) => {
    let readStream = fs.createReadStream(filename);
    readStream.on('readable', () => {
      let arr: Buffer = readStream.read(48);
      // Check if the file starts with the NAV header
      resolve(arr.subarray(40).compare(navHeader) === 0);
    });
  });
}

/**
 * Decodes a runtime package file.
 * @param filename The filename to decode
 * @returns A buffer containing the decoded file.
 */
function decodeNavXFile(filename: fs.PathLike): [Buffer, Boolean] {
  const key = createDecryptionKeyArray();
  const buffer = fs.readFileSync(filename).subarray(48);
  const chunkSize = 81_920;
  let x = 0;
  let y = 0;
  const resultChunks: Buffer[] = [];

  for (let i = 0; i < buffer.length; i += chunkSize) {
    const chunk = buffer.subarray(i, i + chunkSize);
    for (let index = 0; index < chunk.length; ++index) {
      x = (x + 1) & 255;
      y = (y + key[x]) & 255;
      [key[x], key[y]] = [key[y], key[x]];
      const value = key[(key[x] + key[y]) & 255];
      chunk[index] ^= value;
    }
    resultChunks.push(chunk);
  }

  return processZipBuffer(Buffer.concat(resultChunks));
}

/**
 * Processes a zip file buffer, checks for concatenated data, and returns the modified buffer and a flag indicating if concatenated data was found.
 * @param buffer - The buffer representing a zip file.
 * @returns A tuple containing the modified buffer and a boolean indicating if concatenated data was found.
 */
function processZipBuffer(buffer: Buffer): [Buffer, Boolean] {
  const eocdWithoutCommentSize = 22;

  // 0x06054b50 is the signature of the end of central directory record (EOCD)
  const searchBytes = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  const zipEocdIndex = buffer.lastIndexOf(searchBytes);

  if (zipEocdIndex === -1) {
    // Byte sequence not found
    return [buffer, false];
  }

  const header = buffer.subarray(zipEocdIndex, zipEocdIndex + eocdWithoutCommentSize);
  const commentLength = header.readUInt16LE(20);
  const expectedCommentLength = buffer.length - zipEocdIndex - eocdWithoutCommentSize;
  const additionalDataConcatenated = expectedCommentLength > commentLength;

  if (additionalDataConcatenated) {
    buffer = buffer.subarray(0, buffer.length - (expectedCommentLength - commentLength));
  }

  return [buffer, additionalDataConcatenated];
}


/**
 * Decodes a regular file.
 * @param filename The filename to decode
 * @returns A buffer containing the decoded file.
 */
function decodeRegularFile(filename: fs.PathLike): [Buffer, Boolean] {
  let entireBuffer = fs.readFileSync(filename);
  return processZipBuffer(entireBuffer.subarray(40));
}

function readZipFile(zipFileData, isRegularFile, resolve, reject, certificateStripped: Boolean = false) {
  yauzl.fromBuffer(zipFileData, { lazyEntries: true }, (err: Error, zipfile) => {
    if (err) {
      reject([err, certificateStripped]);
      return;
    }

    zipfile.readEntry();
    zipfile.on('entry', (entry) => {
      // Find NavxManifest.xml
      if (/NavxManifest\.xml$/i.test(entry.fileName)) {
        zipfile.openReadStream(entry, (err, readStream) => {
          if (err) {
            reject([err, certificateStripped]);
            return;
          }

          let content = '';
          readStream.on('data', (data) => {
            content += data;
          });

          readStream.on('end', () => {
            xml2js.parseString(content, (err, result) => {
              if (err) {
                reject([err, certificateStripped]);
              } else {
                resolve([result, certificateStripped]);
              }
            });
          });
        });
      } else {
        // Read next entry
        zipfile.readEntry();
      }
    });

    zipfile.on('end', () => {
      reject(new Error('File "NavxManifest.xml" not found in the zip file.'), certificateStripped);
    });
  });
}

/**
 * Extracts the content of NavxManifest.xml from the given file.
 * @param filename The filename to extract the content from.
 * @returns The content of NavxManifest.xml in the given file.
 */
async function extractContentFromZipBuffer(filename: fs.PathLike): Promise<[any, boolean]> {
  let zipFileData: Buffer;
  // Check if the file is a runtime package
  const runtimePackage: boolean = await isRuntimePackage(filename);
  let signed: Boolean;
  if (runtimePackage) {
    [zipFileData, signed] = decodeNavXFile(filename);
  } else {
    [zipFileData, signed] = decodeRegularFile(filename);
  }
  return new Promise((resolve, reject) => {
    readZipFile(zipFileData, !runtimePackage, resolve, reject, signed);
  });
}

/**
 * Contains information about a Business Central app.
 */
type BCInfo = BCBasicInfo & {
  ApplicationVersion: string;
  Platform: string;
  Dependencies?: BCBasicInfo[];
  Description?: string;
  Brief?: string;
  HasCertificate?: boolean;
}

/**
 * Contains basic information about a Business Central app.
 */
type BCBasicInfo = {
  Id: string;
  Name: string;
  Publisher: string;
  Version: string;
}

/**
 * Gets information about a Business Central app.
 * @param filename The filename to get the information from.
 * @returns A promise that resolves to the information about the app.
 */
async function getBCAppInfo(filename: fs.PathLike): Promise<BCInfo> {
  try {
    const [result, certificateStripped] = await extractContentFromZipBuffer(filename);
    const app = result.Package.App[0]['$'];

    // Get dependencies (if any)
    let dependencies: BCBasicInfo[] = result.Package.Dependencies.filter((ele: any) => {
      return ele !== '';
    }).map((ele: any) => {
      const dep = ele.Dependency[0]['$'];
      return {
        Id: dep.Id,
        Name: dep.Name,
        Publisher: dep.Publisher,
        Version: dep.MinVersion,
      };
    });

    const bcInfo: BCInfo = {
      ApplicationVersion: app.Application,
      Publisher: app.Publisher,
      Version: app.Version,
      Name: app.Name,
      Description: app.Description,
      Platform: app.Platform,
      Id: app.Id,
      Brief: app.Brief,
      Dependencies: dependencies,
      HasCertificate: certificateStripped,
    };

    return bcInfo;
  } catch (error) {
    throw error;
  }
}

/**
 * Gets the array of numbers used to decrypt the runtime package.
 * @returns An array of numbers used to decrypt the runtime package.
 */
function createDecryptionKeyArray() {
  // Prepare Key
  const numArray: Uint8Array = new Uint8Array(256);
  for (let index = 0; index < 256; ++index) {
    numArray[index] = index;
  }
  let index1: number = 0;
  let index2: number = 0;
  for (; index1 < 256; ++index1) {
    index2 = (index2 + KeySource[index1 % KeySource.length] + numArray[index1]) & 255;
    [numArray[index1], numArray[index2]] = [numArray[index2], numArray[index1]];
  }
  return numArray;
}

const KeySource = Buffer.from([15, 11, 81, 137, 184, 120]);
const navHeader = Buffer.from([46, 78, 69, 65, 0, 0, 0, 1]);


export {
  isRuntimePackage,
  getBCAppInfo,
};