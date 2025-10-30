const express = require('express');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware
app.use(cors()); // Allow requests from the Chrome extension
app.use(express.json()); // Parse JSON bodies


async function analyzeUrl(url) {
  console.log(`Analyzing URL: ${url}`);

  // --- START Google Safe Browsing API Logic ---

  const GOOGLE_API_KEY = 'AIzaSyCh0OGIGMVG8S6e54uIMrcvcOgr3b76acE'; // Your API key
  const anaylsisUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;

  try {
    const response = await fetch(anaylsisUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client: {
          clientId: 'mindguard-extension',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: url }],
        },
      }),
    });

    // Check if the response itself is okay   
    if (!response.ok) {
      // API key might be invalid or API not enabled 
      console.error(`Google API Error: ${response.status} ${response.statusText}`);
      return {
        safe: null,
        status: 'ERROR',
        message: 'Could not contact Google Safe Browsing. Check API key and quota.',
      };
    }

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      // A threat was found!
      const threatType = data.matches[0].threatType.replace('_', ' ').toLowerCase();
      console.log('Threat detected:', threatType);
      return {
        safe: false,
        status: 'DANGEROUS',
        message: `Warning: This site is flagged for ${threatType}.`,
      };
    } else {
      // No threats found 2
      console.log('No threats found.');
      return {
        safe: true,
        status: 'SAFE',
        message: 'This site appears to be safe.',
      };
    }
  } catch (error) {
    console.error('Error with Safe Browsing API fetch:', error);
    return {
      safe: null,
      status: 'ERROR',
      message: 'Could not analyze this URL. Check server connection.',
    };
  }
  // --- END Google Safe Browsing API Logic ---
}


// API Endpoint for checking a URL 
app.post('/check-url', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const analysisResult = await analyzeUrl(url);
    res.json(analysisResult);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Internal server error during analysis' });
  }
});

app.listen(port, () => {
  console.log(`MindGuard AI server listening on http://localhost:${port}`);
  console.log('Waiting for requests from th Chrome extension...');
});

