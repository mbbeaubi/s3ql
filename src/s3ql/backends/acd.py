
from ..logging import logging # Ensure use of custom logger class
from ..inherit_docstrings import (copy_ancestor_docstring, ABCDocstMeta)
from .common import (AbstractBackend, DanglingStorageURLError, NoSuchObject)

from urllib.parse import urlsplit
logging.getLogger("requests").setLevel(logging.CRITICAL)
import base64
import io
import json
import requests
import datetime
import time
import threading
import tempfile
import hashlib

log = logging.getLogger(__name__)

class Backend(AbstractBackend, metaclass=ABCDocstMeta):
    '''
    A backend that stores data in Google Drive.
    '''

    known_options = {'refresh-token'}

    MIME_TYPE_BINARY = 'application/octet-stream'
    BUFFER_SIZE=1024*16
    MAX_PROPERTY_SIZE = 124
    MAX_REF_CHUNK_SIZE = 100
    VALUE_BASE64 = 'b64:'
    VALUE_REF = 'ref:'
    TOKEN_ENDPOINT='https://api.amazon.com/auth/o2/token'
    ENDPOINT_REQ_URL = 'https://drive.amazonaws.com/drive/v1/account/endpoint'
    APPSPOT_URL = 'https://tensile-runway-92512.appspot.com/'
    exp_time = 0

    # We don't want to request an access token for each instance,
    # because there is a limit on the total number of valid tokens.
    # This class variable holds the mapping from refresh tokens to
    # access tokens.
    _refresh_lock = threading.Lock()

    def __init__(self, storage_url, login, password, options):
        '''Initialize local backend
        Login and password are ignored.
        '''
        # Unused argument
        #pylint: disable=W0613

        super().__init__()
        self.login = "oauth2"

        self.options = options
        self.oauth_data = {}
        self.endpoint_data = {}
        self.oauth_data['refresh_token']=password
        path = storage_url[len('acd://'):].rstrip('/')
        self.s3qlBase = path
        log.debug("Initialize Backend on: /%s" % self.s3qlBase)

        log.debug("Getting credentials")
        self.get_auth_token()
        log.debug(str(self.oauth_data['access_token']))
        log.debug("Get Root Id")
        self.root_node = self._get_rootId()
        foundFiles = self._list_directory(self.root_node['id'],"name:%s" % self.s3qlBase)
        if len(foundFiles) == 0:
            self.s3qlBaseObj = self._create_directory(self.root_node['id'],self.s3qlBase)
        else:
            self.s3qlBaseObj = foundFiles[0]



    def refresh_auth_token(self):
        log.info('Refreshing authentication token.')
        ref = {'refresh_token': self.oauth_data['refresh_token']}
        t = time.time()
        try:
            response = requests.post(self.APPSPOT_URL, data=ref)
        except ConnectionError as e:
            log.info('Error refreshing authentication token.')
            raise requests.Exceptions.RequestError(requests.Exceptions.RequestError.CODE.CONN_EXCEPTION, e.__str__())

        if response.status_code != requests.codes.ok:
            raise requests.Exceptions.RequestError(requests.Exceptions.RequestError.CODE.REFRESH_FAILED,
                               'Error refreshing authentication token: %s' % response.text)

        r = self.validate(response.text)
        self.oauth_data = r
        self.treat_auth_token(t)


    def validate(cls, oauth: str) -> dict:

        try:
            o = json.loads(oauth)
            o['access_token']
            o['expires_in']
            o['refresh_token']
            return o
        except (ValueError, KeyError) as e:
            log.info('Invalid authentication token: Invalid JSON or missing key.'
                            'Token:\n%s' % oauth)
            raise requests.Exceptions.RequestError(requests.Exceptions.RequestError.CODE.INVALID_TOKEN, e.__str__())

    def treat_auth_token(self, time_: float):
        """Adds expiration time to member OAuth dict using specified begin time."""
        self.exp_time = time_ + self.oauth_data['expires_in'] - 120
        self.oauth_data['exp_time'] = self.exp_time
        log.info('New token expires at %s.'
                    % datetime.datetime.fromtimestamp(self.exp_time).isoformat(' '))


    def get_auth_token(self, reload=True) -> str:
        with self._refresh_lock:
            if self.exp_time is None or time.time() > self.exp_time:
                log.info('Token expired at %s.' % datetime.datetime.fromtimestamp(self.exp_time).isoformat(' '))
                self.refresh_auth_token()
                self._get_endpoints()

    def _get_rootId(self):
        r = requests.get(self.endpoint_data['metadataUrl']+"nodes?filters=isRoot:true", headers = {'Authorization':"Bearer " + self.oauth_data['access_token']})
        self.check_valid_response(r)
        return r.json()['data'][0]

    def _create_directory(self,parentID,name):
        self.get_auth_token()
        r = requests.post(self.endpoint_data['metadataUrl']+"nodes",json={'name':name,'kind':'FOLDER','parents':[parentID]}, headers = {'Authorization':"Bearer " + self.oauth_data['access_token']})
        self.check_valid_response(r)
        return r.json()

    def _get_metadata_object(self,nodeID):
        self.get_auth_token()
        r = requests.get(self.endpoint_data['metadataUrl']+"nodes/%s" % nodeID, headers = {'Authorization':"Bearer " + self.oauth_data['access_token']})
        self.check_valid_response(r)
        return r.json()



    def _list_directory(self,directoryID,filters=None,startToken=None):
        self.get_auth_token()
        filterString="?limit=200"
        if filters is not None:
            filterString+="&filters=%s" % filters
        if startToken is not None:
            filterString+="&startToken=%s" % startToken
        r = requests.get(self.endpoint_data['metadataUrl']+"nodes/%s/children%s" % (directoryID,filterString), headers = {'Authorization':"Bearer " + self.oauth_data['access_token']})
        self.check_valid_response(r)
        json = r.json()
        objects = {}
        if int(json['count']) > 0:
            objects = json['data']
            if json.get('nextToken'):
                objects = objects + self._list_directory(self,directoryID,filters,json['nextToken'])
        return objects


    def check_valid_response(self,response):
        if response.status_code not in [200,201]:
            log.error('Error code Response %s: %s' % (response.status_code,response.text))
            raise Exception


    def _get_endpoints(self) -> dict:
        r = requests.get(self.ENDPOINT_REQ_URL, headers = {'Authorization':"Bearer " + self.oauth_data['access_token']})


        try:
            e = r.json()
        except ValueError as e:
            log.error('Invalid JSON: "%s"' % r.text)
            raise e

        self.endpoint_data = e

        try:
            log.debug("New MetaURL %s" % self.endpoint_data['metadataUrl'])
            log.debug("New ContentURL %s" % self.endpoint_data['contentUrl'])
        except KeyError as e:
            log.error('Received invalid endpoint data.')
            raise e


    def _lookup_file(self, name):

        fileLookUpObj= self._list_directory(self.s3qlBaseObj['id'],"name:%s" % name)
        if len(fileLookUpObj)==0:
            return None
        return fileLookUpObj[0]





    def _delete_file(self, f):
        self.get_auth_token()
        headers = dict()
        headers['Authorization'] = "Bearer " + self.oauth_data['access_token']
        url = self.endpoint_data['metadataUrl']+"trash/%s" % f['id']
        r = requests.put(url,json={"kind":"FILE","name":"S3QL-trash-%s" % f['id']}, headers = headers)
        self.check_valid_response(r)

    def _encode_metadata(self, metadata):
        properties = []
        for key in metadata.keys():
            keyMark = "S3QL-"+key
            val = metadata[key]
            if isinstance(val, bytes):
                val = "b64-"+base64.b64encode(val).decode('utf-8')

            label=keyMark + ":" + str(val)
            if len(label)<=255:
                properties.append(label)
            else:
                chunks = [val[i:i+255-len(keyMark)-3] for i in range(0, len(val), 255-len(keyMark)-3)]
                for i, chunk in enumerate(chunks):
                    if i==0:

                        properties.append(keyMark+"-R:"+ chunk)
                    else:
                        properties.append("SREF-"+key+"-%d" % (i-1) +":"+ chunk)

        return properties


    def _decode_metadata(self,f):
        metadata = dict()
        properties = f['labels']
        if properties is not None:
            for property in properties:
                propertyKey,propertyValue = property.split(':')
                metaKey = propertyKey.split("-")[1]
                if propertyKey.startswith("S3QL-"):
                    if propertyKey.endswith("-R"):
                        for chunk in sorted(filter(lambda x: x.startswith("SREF-"+propertyKey.split("-")[1]), properties)):
                            propertyValue+=chunk.split(":")[1]

                    if propertyValue.startswith("b64-"):
                        propertyValue=base64.b64decode(propertyValue[4:])
                    elif propertyValue.isdigit():
                        propertyValue = int(propertyValue)
                    metadata[metaKey] = propertyValue
                    ##log.debug('{0}: metadata {1}={2}'.format(f['name'], metaKey,propertyValue))
            return metadata

    @property
    @copy_ancestor_docstring
    def has_native_rename(self):
        return False

    def __str__(self):
        return 'Amazon Cloud Drive folder %s' % self.s3qlBase

    @copy_ancestor_docstring
    def is_temp_failure(self, exc): #IGNORE:W0613
        return False

    @copy_ancestor_docstring
    def lookup(self, key):
        log.debug("lookup {0}".format(key))
        f = self._lookup_file(key)
        if f is None or f['id'] is None:
            raise NoSuchObject(key)
        return self._decode_metadata(f)

    @copy_ancestor_docstring
    def get_size(self, key):
        log.debug("get_size {0}".format(key))
        f = self._lookup_file(key )
        if f is None:
            raise NoSuchObject(key)
        return int(f.get('size', u'0'))

    @copy_ancestor_docstring
    def open_read(self, key,orig = None):
        log.debug("open_read {0} {1}".format(key,orig))
        f = self._lookup_file(key )
        if f is None or f['id'] is None:
            raise NoSuchObject(key)
        return ObjectR(self,f,self._decode_metadata(f))

    @copy_ancestor_docstring
    def open_write(self, key, metadata=None, is_compressed=False):
        log.debug("open_write {0}".format(key))

        self.delete(key,True)

        if metadata is None:
            metadata = dict()
        elif not isinstance(metadata, dict):
            raise TypeError('*metadata*: expected dict or None, got %s' % type(metadata))

        amazonMetadata = {}
        amazonMetadata["name"]= key
        amazonMetadata["kind"] ="FILE"
        amazonMetadata["parents"] = [self.s3qlBaseObj['id']]
        amazonMetadata["labels"] = self._encode_metadata(metadata=metadata)
        #log.debug("open_write %s with %s" % (key,str(amazonMetadata)))
        ##If exist delete first

        #TOD@
        return ObjectW(self,key,amazonMetadata)

    @copy_ancestor_docstring
    def clear(self):
        log.debug("clear")
        for f in self._list_files(self.folder, "id"):
            self._delete_file(f)

    @copy_ancestor_docstring
    def contains(self, key):
        log.debug("contains {0}".format(key))
        f = self._lookup_file(key )
        return f is not None

    @copy_ancestor_docstring
    def delete(self, key, force=False):
        f = self._lookup_file(key)
        if f is not None and f['id'] is not None:
            log.debug("delete {0}".format(key))
            self._delete_file(f)
        elif not force:
            raise NoSuchObject(key)


    @copy_ancestor_docstring
    def list(self, prefix=''):
        log.debug("list {0}".format(prefix))
        for f in self._list_directory(self.root_node['id'],"name:%s*" % prefix):
            name = f['name']
            if not prefix or name.startswith(prefix):
                yield name

    @copy_ancestor_docstring
    def update_meta(self, key, metadata):
        log.debug("update_meta {0}: {1}".format(key, metadata))
        if not isinstance(metadata, dict):
            raise TypeError('*metadata*: expected dict, got %s' % type(metadata))
        self.copy(key, key, metadata)

    @copy_ancestor_docstring
    def copy(self, src, dest, metadata=None):
        log.debug("copy {0} -> {1}".format(src, dest))
        if not (metadata is None or isinstance(metadata, dict)):
            raise TypeError('*metadata*: expected dict or None, got %s' % type(metadata))

        ##Only Update metadata
        if src == dest:
            log.debug("Only updating metadata: %s" % src)
            self._update_metadata(src,metadata)
        else:
            ##Download the file
            fhr = self.open_read(src,"copy")
            bytedata = fhr.read(self.BUFFER_SIZE)
            fhr.close()
            fhw = self.open_write(dest,metadata)
            fhw.write(bytedata)
            fhw.close()

    def _update_metadata(self, key,metadata):
        fileMetadata = self._lookup_file(key)
        encodedMetadata = self._encode_metadata(metadata=metadata)
        r = requests.patch(self.endpoint_data['metadataUrl']+"nodes/%s" % fileMetadata['id'],json={"labels":encodedMetadata}, headers = {'Authorization':"Bearer " + self.oauth_data['access_token']})
        self.check_valid_response(r)


class ObjectR(object):
    '''A Google Drive object opened for reading'''

    def __init__(self, backend, f, metadata):
        super().__init__()
        self.metadata = metadata
        self.backend=backend
        self.f=f
        self.md5 = hashlib.md5()
        self.md5_checked=False
        self.response=None
        self.closed=False
        self.backend.get_auth_token()
        url = self.backend.endpoint_data['contentUrl']+"nodes/%s/content" % self.f['id']
        self.response = requests.get(url, headers = {'Authorization':"Bearer " + self.backend.oauth_data['access_token']},stream=True)
        if self.response.status_code not in [200,201]:
            log.error('Unexpected server response. Expected data, got:\n'
                      '%d %s\n%s\n\n%s', self.response.status_code, self.response.reason,
                      '\n'.join('%s' % str(x) for x in self.response.headers.items()))

    def read(self, size=None):
        '''Read up to *size* bytes of object data

        For integrity checking to work, this method has to be called until
        it returns an empty string, indicating that all data has been read
        (and verified).
        '''


        if size == 0:
            return b''

        buf = self.response.raw.read(size)
        self.md5.update(buf)

        if (not buf or size is None) and not self.md5_checked:
            etag = self.response.headers['ETag'].strip('"')
            self.md5_checked = True
            if etag != self.md5.hexdigest():
                log.warning('MD5 mismatch for %s(%s): Etag:%s vs downloaded MD5:%s',
                            self.f['name'],self.f['id'],etag, self.md5.hexdigest())
                #log.debug("Bearer %s" % self.backend.oauth_data['access_token'])
                raise BadDigestError('BadDigest','ETag header does not agree with calculated MD5')
        return buf

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False

    def close(self, checksum_warning=True):
        '''Close object

        If *checksum_warning* is true, this will generate a warning message if
        the object has not been fully read (because in that case the MD5
        checksum cannot be checked).
        '''

        if self.closed:
            return
        self.closed = True
        self.response.close()

        # If we have not read all the data, close the entire
        # connection (otherwise we loose synchronization)
        if not self.md5_checked:
            if checksum_warning:
                log.warning("Object closed prematurely, can't check MD5, and have to "
                            "reset connection")
            if self.response is not None:
                self.response.connection.close()



class ObjectW(object):
    '''A Google Drive object opened for writing'''

    def __init__(self,amazonCloudDrive, key,metadata):
        super().__init__()
        self.key = key
        self.metadata=metadata
        self.amazonCloudDrive=amazonCloudDrive
        self.closed = False
        self.obj_size = 0
        # According to http://docs.python.org/3/library/functions.html#open
        # the buffer size is typically ~8 kB. We process data in much
        # larger chunks, so buffering would only hurt performance.
        self.fh = tempfile.TemporaryFile(buffering=0)

        # False positive, hashlib *does* have md5 member
        #pylint: disable=E1101
        self.md5 = hashlib.md5()

    def write(self, buf):
        '''Write object data'''

        self.fh.write(buf)
        self.md5.update(buf)
        self.obj_size += len(buf)

    def close(self):
        if self.closed:
            # still call fh.close, may have generated an error before
            self.fh.close()
            return

        self.fh.seek(0)
        #Upload
        self.amazonCloudDrive.get_auth_token()
        resp = self.upload(metadata=self.metadata,buf=self.fh)
        if resp.status_code not in [200,201]:
            log.error('Unexpected server response. Expected nothing, got:\n'
                      '%d %s\n%s\n\n%s', resp.status_code, resp.reason,
                      '\n'.join('%s' % x for x in resp.headers.items()))
            raise RuntimeError('Unexpected server response')
        json = resp.json()
        md5 = json['contentProperties']['md5']
        if md5 != self.md5.hexdigest():
            # delete may fail, but we don't want to loose the BadDigest exception
            try:
                self.amazonCloudDrive.delete(self.key)
            finally:
                raise BadDigestError('BadDigest', 'MD5 mismatch for %s (received: %s, sent: %s)' %
                                     (self.key, md5, self.md5.hexdigest()))

        self.closed = True
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False

    def get_obj_size(self):
        if not self.closed:
            raise RuntimeError('Object must be closed first.')
        return self.obj_size

    def upload(self,metadata, buf):
        """
        fields is a dict of (name, value) elements for regular form fields.
        files is a dict of (filename, filedata) elements for data to be uploaded as files
        Return (content_type, body) ready for httplib.HTTP instance
        """

        headers = dict()
        headers['Authorization'] = "Bearer " + self.amazonCloudDrive.oauth_data['access_token']

        #r = requests.post(self.amazonCloudDrive.endpoint_data['contentUrl']+"nodes",data=body, headers = headers)
        files = {"content":(metadata['name'],buf,"application/octet-stream")}
        data = {"metadata":json.dumps(metadata)}
        r = requests.post(self.amazonCloudDrive.endpoint_data['contentUrl']+"nodes?suppress=deduplication",files=files,data=data, headers = headers)

        self.amazonCloudDrive.check_valid_response(r)
        return r

class S3Error(Exception):
    '''
    Represents an error returned by S3. For possible codes, see
    http://docs.amazonwebservices.com/AmazonS3/latest/API/ErrorResponses.html
    '''

    def __init__(self, code, msg, headers=None):
        super().__init__(msg)
        self.code = code
        self.msg = msg


    def __str__(self):
        return '%s: %s' % (self.code, self.msg)
class BadDigestError(S3Error): pass