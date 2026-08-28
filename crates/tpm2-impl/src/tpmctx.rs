use crate::ServerError;
use crate::buffers::{InOutBuffer, SeparateBuffers};
use crate::handler::CommandHandler;
use crate::platform::{TpmBuffers, TpmContextDeps, TpmReadBuffer, TpmWriteBuffer};
use crate::req_resp::RequestResponseCursor;
use tpm2::{TpmCc, errors::TpmRc};

/// The object that processes incoming TPM requests and produces the corresponding TPM response.
pub struct TpmContext<Deps: TpmContextDeps> {
    handler: CommandHandler<Deps>,
}

impl<Deps: TpmContextDeps> TpmContext<Deps> {
    /// Creates a new [`TpmContext`] object that processes incoming TPM requests.
    pub fn new() -> Result<Self, ServerError> {
        Ok(Self {
            handler: CommandHandler::new()?,
        })
    }

    /// Process a TPM request and writes the response in a separate buffer. Returns the number of
    /// bytes written to the response buffer.
    pub fn execute_command_separate(
        &mut self,
        request: &Deps::Request,
        response: &mut Deps::Response,
    ) -> usize {
        let buf = SeparateBuffers::new(request, response);
        match self.execute_command(buf) {
            Ok(size) => size,
            Err(err) => self.fill_error(response, err),
        }
    }

    /// Process a TPM request and write the response back into the same buffer. Returns the number
    /// of bytes written to the response buffer.
    pub fn execute_command_in_place(
        &mut self,
        in_out: &mut Deps::Response,
        request_size: usize,
    ) -> usize {
        let buf = InOutBuffer::new(in_out, request_size);
        match self.execute_command(buf) {
            Ok(size) => size,
            Err(err) => self.fill_error(in_out, err),
        }
    }

    fn fill_error(&mut self, response: &mut Deps::Response, error: TpmRc) -> usize {
        // TODO fill out more of the TPM header for an error
        if response.write(6, &error.get().to_be_bytes()).is_err() {
            return 0;
        }
        10
    }

    fn execute_command(&mut self, buffers: impl TpmBuffers) -> Result<usize, TpmRc> {
        let request_size = buffers.get_request().len();
        const CMD_HANDLER_RESPONSE_OFFSET: usize = 10;
        let mut request_and_response =
            RequestResponseCursor::new(buffers, CMD_HANDLER_RESPONSE_OFFSET);
        let mut request = request_and_response.request();
        let _session = request.read_be_u16().ok_or(TpmRc::COMMAND_SIZE)?;
        let size = request.read_be_u32().ok_or(TpmRc::COMMAND_SIZE)?;
        if size as usize != request_size {
            return Err(TpmRc::COMMAND_SIZE);
        }
        let command_code = request.read_be_u32().ok_or(TpmRc::COMMAND_SIZE)?;

        // TODO, if _session is not NoSession, then parse session stuff here

        match TpmCc::from(command_code) {
            TpmCc::GetRandom => self.handler.get_random(request),
            _ => Err(TpmRc::COMMAND_CODE),
        }?;

        let response_size = request_and_response.last_response_byte_written();
        let response = request_and_response.response();
        // TODO add session information
        let session_tag = 0x8001_u16;
        response
            .write(0, &(session_tag).to_be_bytes())
            .map_err(|_| TpmRc::MEMORY)?;

        response
            .write(2, &(response_size as u32).to_be_bytes())
            .map_err(|_| TpmRc::MEMORY)?;
        const SUCCESS_STATUS: u32 = 0;
        response
            .write(6, &SUCCESS_STATUS.to_be_bytes())
            .map_err(|_| TpmRc::MEMORY)?;

        Ok(response_size)
    }
}
