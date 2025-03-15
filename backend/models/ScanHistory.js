const mongoose = require('mongoose');

const ScanHistorySchema = new mongoose.Schema({
    scanType: {
      type: String,
      enum: ['url', 'email'],
      required: true
    },
    target: {
      type: String,
      required: true
    },
    scanDate: {
      type: Date,
      default: Date.now
    },
    virusTotalResults: {
      type: Object,
      default: null
    },
    safeBrowsingResults: {
      type: Object,
      default: null
    },
    isMalicious: {
      type: Boolean,
      default: false
    },
    threatScore: {
      type: Number,
      default: 0
    }
});
  
module.exports = mongoose.model('ScanHistory', ScanHistorySchema)