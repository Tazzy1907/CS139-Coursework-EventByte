# File to create bar codes. Kept in a seperate file as irrelevant to rest of the main python files.
from barcode import EAN13

def createBarcode(ticketRef):
    '''
    @param ticketRef - Int
    '''
    strTicketRef = ((12 - len(str(ticketRef))) * "0") + str(ticketRef) +"0"
    
    myCode = EAN13(strTicketRef)
    myCode.save("static/images/currBarCode")
