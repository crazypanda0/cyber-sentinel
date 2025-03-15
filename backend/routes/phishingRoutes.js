const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const ScanHistory = require('../models/ScanHistory');
const verifyToken = require('../middlewares/authMiddleware');
const { emailSchema, urlSchema } = require('../validation/phishingValidation');

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GOOGLE_SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

// Helper function to check URL with VirusTotal
async function checkUrlWithVirusTotal(url) {
    try {
      const encodedUrl = encodeURIComponent(url);
      const urlId = crypto.createHash('sha256').update(url).digest('hex');
      
      const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      });
      console.log("jai ho ", response.data);
      return response.data;
    } catch (error) {
      if (error.response && error.response.status === 404) {
        try {
          const formData = new URLSearchParams();
          formData.append('url', url);
          
          const submitResponse = await axios.post('https://www.virustotal.com/api/v3/urls', formData, {
            headers: {
              'x-apikey': VIRUSTOTAL_API_KEY,
              'Content-Type': 'application/x-www-form-urlencoded'
            }
          });
          
          const analysisId = submitResponse.data.data.id;
          await new Promise(resolve => setTimeout(resolve, 5000));
          
          const analysisResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: {
              'x-apikey': VIRUSTOTAL_API_KEY
            }
          });
          console.log("hellobcbfbfbfdbfgbfg ", analysisResponse.data);
          return analysisResponse.data;
        } catch (submitError) {
          console.error('Error submitting URL to VirusTotal:', submitError.message);
          throw submitError;
        }
      }
      
    console.error('Error checking URL with VirusTotal:', error.message);
    throw error;
  }
}
  
// Helper function to check URL with Google Safe Browsing
async function checkUrlWithSafeBrowsing(url) {
  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_KEY}`,
      {
        client: {
          clientId: "your-client-name",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }], // Directly use the single URL
        },
      }
    );

    console.log(response.data);
    return response.data;
  } catch (error) {
    console.error("Error checking URL with Google Safe Browsing:", error.message);
    throw error;
  }
}
  
// Helper function to analyze an email for phishing indicators
async function analyzeEmail(emailContent) {
  // Extract URLs from email
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = emailContent.match(urlRegex) || [];
  
  // Check each URL
  const urlResults = [];
  for (const url of urls) {
    try {
      const vtResult = await checkUrlWithVirusTotal(url);
      const sbResult = await checkUrlWithSafeBrowsing(url);
      
      urlResults.push({
        url,
        virusTotal: vtResult,
        safeBrowsing: sbResult,
        isMalicious: isUrlMalicious(vtResult, sbResult)
      });
    } catch (error) {
      console.error(`Error checking URL ${url} in email:`, error.message);
      urlResults.push({ url, error: error.message });
    }
  }
  
  // Check for other phishing indicators
  const indicators = {
    suspiciousLinks: urlResults.filter(result => result.isMalicious).length > 0,
    urgencyLanguage: /urgent|immediately|verify|suspend|account|password|banking|update|confirm/i.test(emailContent),
    poorGrammar: false,
    mismatchedDomains: false
  };
  
  // Calculate threat score
  let threatScore = 0;
  if (indicators.suspiciousLinks) threatScore += 50;
  if (indicators.urgencyLanguage) threatScore += 20;
  
  return {
    urlResults,
    indicators,
    threatScore,
    isMalicious: threatScore > 30
  };
}
  
// Helper function to determine if a URL is malicious based on API results
function isUrlMalicious(vtResult, sbResult) {
  let isMalicious = false;
  
  // Check VirusTotal results
  if(vtResult && vtResult.data && vtResult.data.attributes) {
    const stats = vtResult.data.attributes.last_analysis_stats;
    if (stats && (stats.malicious > 0 || stats.suspicious > 0)) {
      isMalicious = true;
    }
  }
  
  // Check Google Safe Browsing results
  if(sbResult && sbResult.matches && sbResult.matches.length > 0) {
    isMalicious = true;
  }
  
  return isMalicious;
}
  
// Route to check a URL for phishing
router.post('/check-url', verifyToken, async (req, res) => {
  try {
    const validatedData = urlSchema.parse(req.body);
    const { url } = validatedData;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Check with VirusTotal
    const vtResult = await checkUrlWithVirusTotal(url);
    
    // Check with Google Safe Browsing
    const sbResult = await checkUrlWithSafeBrowsing(url);
    
    // Determine if the URL is malicious
    const isMalicious = isUrlMalicious(vtResult, sbResult);
    
    // Calculate threat score
    let threatScore = 0;
    
    if(vtResult && vtResult.data && vtResult.data.attributes) {
      const stats = vtResult.data.attributes.last_analysis_stats;
      console.log(stats);
      if (stats) {
        threatScore += (stats.malicious * 5) + (stats.suspicious * 2);
      }
    }
    
    console.log(sbResult)
    if(sbResult && sbResult.matches && sbResult.matches.length > 0) {
      threatScore += 30;
    }
    
    // Store scan history
    const scanHistory = new ScanHistory({
      scanType: 'url',
      target: url,
      virusTotalResults: vtResult,
      safeBrowsingResults: sbResult,
      isMalicious,
      threatScore
    });
    
    await scanHistory.save();
    
    // Send response
    res.json({
      url,
      isMalicious,
      threatScore,
      scanId: scanHistory._id,
      virusTotalResults: vtResult,
      safeBrowsingResults: sbResult
    });
    
  } catch (error) {
    console.error('Error in /check-url route:', error.message);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});
  
// Route to check an email for phishing
router.post('/check-email', verifyToken, async (req, res) => {
  try {
    const validatedData = emailSchema.parse(req.body);
    const { email, emailContent } = validatedData;
    
    if (!email || !emailContent) {
      return res.status(400).json({ error: 'Email address and content are required' });
    }
    
    // Analyze the email
    const analysisResult = await analyzeEmail(emailContent);
    
    // Store scan history
    const scanHistory = new ScanHistory({
      scanType: 'email',
      target: email,
      virusTotalResults: analysisResult.urlResults.map(r => r.virusTotal),
      safeBrowsingResults: analysisResult.urlResults.map(r => r.safeBrowsing),
      isMalicious: analysisResult.isMalicious,
      threatScore: analysisResult.threatScore
    });
    
    await scanHistory.save();
    
    // Send response
    res.json({
      email,
      isMalicious: analysisResult.isMalicious,
      threatScore: analysisResult.threatScore,
      scanId: scanHistory._id,
      indicators: analysisResult.indicators,
      urlResults: analysisResult.urlResults.map(r => ({
          url: r.url,
          isMalicious: r.isMalicious
      }))
    });
  } catch (error) {
      console.error('Error in /check-email route:', error.message);
      res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});
  
// Route to get scan history
router.get('/history', verifyToken, async (req, res) => {
  try {
    const { limit = 20, page = 1, scanType } = req.query;
    
    const query = {};
    if (scanType) {
      query.scanType = scanType;
    }
    
    const scanHistory = await ScanHistory.find(query)
    .sort({ scanDate: -1 })
    .limit(parseInt(limit))
    .skip((parseInt(page) - 1) * parseInt(limit))
    .select('-virusTotalResults -safeBrowsingResults'); // Exclude large objects
    
    const totalCount = await ScanHistory.countDocuments(query);
    
    res.json({
      totalCount,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(totalCount / parseInt(limit)),
      data: scanHistory
    });
  } catch (error) {
      console.error('Error in /history route:', error.message);
      res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});
  
// Route to get detailed scan result by ID
router.get('/history/:id', verifyToken, async (req, res) => {
  try {
    const scanHistory = await ScanHistory.findById(req.params.id);
    
    if (!scanHistory) {
      return res.status(404).json({ error: 'Scan history not found' });
    }
    
    res.json(scanHistory);
    
  } catch (error) {
    console.error('Error in /history/:id route:', error.message);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});
  
module.exports = router;