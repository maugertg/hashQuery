import sys
import requests

from datetime import datetime
from urllib.parse import urljoin

class Threatgrid():
    
    def __init__(self, host, api_key) -> None:
        self.session = requests.Session()
        self.api_key = api_key
        self.base_url = f'https://{host}'

    @staticmethod
    def errors(query: str) -> bool:
        return bool(type(query) == str and query[:5] == 'Error')

    def query_api (self, query: str):
        query = urljoin(self.base_url, '/api/v2'+query)
        response = self.get(query)
        self.retry(response, query)
        return response

    def get(self, query: str) -> dict:
        try:
            response = self.session.get(query, json={'api_key': f'{self.api_key}'})
            if response.status_code // 100 != 2:
                return "Error: {}".format(response)
            return response.json()
        except requests.exceptions.RequestException as e:
            return 'Error Exception: {}'.format(e)

    def retry (self, query: str, url: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Check for errors and retry upto 3 times
        retry_limit = 3
        while self.errors(query) == True and retry_limit > 0:
            # Write the error with time, error, and URL
            with open('Errors.txt','a') as f:
                f.write("{} {} - {}\n".format(timestamp, query, url))
            print('Error recieved retryining %s times' % retry_limit)
            
            # Retry the same query
            query = self.get(url)
            retry_limit -= 1
            
            # Exit after retrying 3 times
            if retry_limit == 0:
                with open('Errors.txt','a') as f:
                    f.write("{} Error: Maximum Retry Reached - {}\n".format(timestamp, url))
                    sys.exit()


    def paginate (self, url ):
        # Container for results
        results = []

        # Setup parameters for pagination
        limit = 100
        returns = limit
        offset = 0
        total = 0

        # Loop to page through the results if the number of results is greater than the limit
        while returns >= limit:
            pagination_params = '&offset={}&limit={}'.format(offset,limit)
            query = self.query_api(url+pagination_params)
            results.append(query)
            returns = query['data']['current_item_count']
            total += returns
            offset += limit
        return results