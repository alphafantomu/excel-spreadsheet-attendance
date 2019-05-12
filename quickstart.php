<?php
require __DIR__ . '/vendor/autoload.php';

if (php_sapi_name() != 'cli') {
    throw new Exception('This application must be run on the command line.');
}

/**
 * Returns an authorized API client.
 * @return Google_Client the authorized client object
 */

function getClient() //don't need to modify this
{
    $client = new Google_Client();
    $client->setApplicationName('Google Sheets API PHP Quickstart');
    $client->setScopes(['https://www.googleapis.com/auth/drive','https://spreadsheets.google.com/feeds']);
    $client->setAuthConfig('credentials.json');
    $client->setAccessType('offline');
    $client->setPrompt('select_account consent');
	$client->addScope(Google_Service_Sheets::SPREADSHEETS);
    // Load previously authorized token from a file, if it exists.
    // The file token.json stores the user's access and refresh tokens, and is
    // created automatically when the authorization flow completes for the first
    // time.
    $tokenPath = 'token.json';
    if (file_exists($tokenPath)) {
        $accessToken = json_decode(file_get_contents($tokenPath), true);
        $client->setAccessToken($accessToken);
    }

    // If there is no previous token or it's expired.
    if ($client->isAccessTokenExpired()) {
        // Refresh the token if possible, else fetch a new one.
        if ($client->getRefreshToken()) {
            $client->fetchAccessTokenWithRefreshToken($client->getRefreshToken());
        } else {
            // Request authorization from the user.
            $authUrl = $client->createAuthUrl();
            printf("Open the following link in your browser:\n%s\n", $authUrl);
            print 'Enter verification code: ';
            $authCode = trim(fgets(STDIN));

            // Exchange authorization code for an access token.
            $accessToken = $client->fetchAccessTokenWithAuthCode($authCode);
            $client->setAccessToken($accessToken);

            // Check to see if there was an error.
            if (array_key_exists('error', $accessToken)) {
                throw new Exception(join(', ', $accessToken));
            }
        }
        // Save the token to a file.
        if (!file_exists(dirname($tokenPath))) {
            mkdir(dirname($tokenPath), 0700, true);
        }
        file_put_contents($tokenPath, json_encode($client->getAccessToken()));
    }
    return $client;
}


// Get the API client and construct the service object.
$client = getClient();
$service = new Google_Service_Sheets($client);

// Prints the names and majors of students in a sample spreadsheet:
// https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit
//php quickstart.php gr SheetName A1:E75 SheetId
//php quickstart.php ec SheetName A1 SheetId Value

//yeah so im like god damn it php cml, i cant input an entire goddamn string and it's just disappearing and I cant put random spaces
//new method??
//php quickstart.php ec ["SheetName", "A1", "SheetId", ["Lol", "Whats up?"]]
//convert JSON(str, true) to an ascii string in Lua
//which means there will only be $argv[1] and $argv[2].

//php quickstart.php ec SheetName A1 SheetId 1
//php argv[0] argv[1] argv[2] argv[3] argv[4] argv[5] argv[6]
//argv[5] is the row index, like A6 (6 is the index)
//argv[6] is the line the data found is on

if (count($argv) <= 0) {
	exit(0);
	echo 'Invalid number of arguments';
};

$spreadsheetId = $argv[4]; //'1OnApSQ09shaZ06TriU0l7BAa_wf8KpJ_m2Eyevk02kc';
$sheetName = $argv[2];
$range = $sheetName.'!'.$argv[3];//'Sheet1!A2:B';
date_default_timezone_set('America/New_York');

if ($argv[1] == 'gr') {
	$response = $service->spreadsheets_values->get($spreadsheetId, $range, ['majorDimension' => 'COLUMNS']);
	$spreadsheetValues = $response['values'];
	echo json_encode($spreadsheetValues)."\n";
} else if ($argv[1] == 'ec') {
	//if ($argv[3] == "NONE") {exit(0);}; end;
	
	
	//$rowNeed = $rows['values'][$argv[5]];
	
	//grab source, get line of source and seperate the table
	$db = file("batman.csv"); //db file
	$dataline = $db[$argv[6] - 1]; //yeah lua is stupid and starts at 1, php starts at 0
	$array = explode(',', $dataline);
	
	$charactersToChange = array("B","C","D","E","F");
	$range = $sheetName.'!'."A".($argv[5]).":".end($charactersToChange);
	$rows = $service->spreadsheets_values->get($spreadsheetId, $range, ['majorDimension' => 'ROWS']);
	
	$arrayIndex = 0;
	foreach ($charactersToChange as $value) {
		$updateRange = $value.$argv[5];
		$toInput = trim(preg_replace('/\s\s+/', ' ', $array[$arrayIndex + 1]));
		if ($value == end($charactersToChange)) {
			$toInput = date('m/d/Y h:i:s a', time());
		};
		$updateBody = new Google_Service_Sheets_ValueRange([
			'range' => $updateRange,
			'majorDimension' => 'ROWS',
			'values' => ['values' => $toInput]
		]);
		$service->spreadsheets_values->update(
			$spreadsheetId,
			$updateRange,
			$updateBody,
			['valueInputOption' => 'USER_ENTERED']
		);
		$arrayIndex++;
	}
	
	/*
	if ($argv[3] == "NONE") {
		$range = 
	}
	$data = array();
	$data[] = new Google_Service_Sheets_ValueRange(array(
		'range' => $range,
		'values' => array([$argv[5]])
	));
	echo $argv[5];
	echo var_dump(json_decode($argv[5], true));
	$postBody = new Google_Service_Sheets_BatchUpdateValuesRequest(
		array(
			'valueInputOption' => "USER_ENTERED",
			'data' => $data
		)
	);
	$response = $service->spreadsheets_values->batchUpdate($spreadsheetId, $postBody);
	*/
} else {
	exit(0);
	echo 'Please enter valid arguments into the command line';
};
//echo '<pre>', var_export($response, true), '</pre>', "\n";
//echo $response['values'][0][1]."\n";
//echo '<pre>',var_dump($argv), '</pre>', "\n";
?>





















