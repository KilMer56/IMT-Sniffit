from elasticsearch import Elasticsearch
es = Elasticsearch([{'host': 'localhost', 'port':9200}])

def post_data(timestamp, size):
    """
    Index data in the ElasticSearch index

    :param timestamp : timestamp of the data
    :type timestamp : long

    :param size : size of the data
    :type size : int
    """
    #  TODO
    # es.index(index="sniffer_data", doc_type="packet", body={times})
