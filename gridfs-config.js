const mongoose = require('mongoose');
const { GridFSBucket } = require('mongodb');
const stream = require('stream');

let bucket;

// Initialize GridFS when MongoDB connects
const initGridFS = () => {
    bucket = new GridFSBucket(mongoose.connection.db, {
        bucketName: 'audioUploads'
    });
    console.log('GridFS bucket initialized');
    return bucket;
};

// Get the GridFS bucket
const getBucket = () => {
    if (!bucket) {
        throw new Error('GridFS not initialized');
    }
    return bucket;
};

// Upload a buffer to GridFS
const uploadBuffer = async (buffer, filename, contentType) => {
    const bufferStream = new stream.PassThrough();
    bufferStream.end(buffer);
    
    const uploadStream = getBucket().openUploadStream(filename, {
        contentType
    });
    
    return new Promise((resolve, reject) => {
        bufferStream.pipe(uploadStream)
            .on('error', reject)
            .on('finish', () => resolve(uploadStream.id));
    });
};

// Download a file from GridFS by filename
const createDownloadStreamByName = (filename) => {
    return getBucket().openDownloadStreamByName(filename);
};

// Delete a file from GridFS
const deleteFile = async (filename) => {
    const files = await mongoose.connection.db
        .collection('audioUploads.files')
        .find({ filename })
        .toArray();
    
    if (files.length > 0) {
        await getBucket().delete(files[0]._id);
        return true;
    }
    
    return false;
};

module.exports = {
    initGridFS,
    getBucket,
    uploadBuffer,
    createDownloadStreamByName,
    deleteFile
};
