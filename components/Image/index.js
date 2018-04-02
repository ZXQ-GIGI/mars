/*
 * @Author: zhaoxiaoqi
 * @Date: 2018-04-02 16:22:05
 * @Last Modified by: zhaoxiaoqi
 * @Last Modified time: 2018-04-02 16:25:03
 */

import React, { PureComponent } from 'react';
import { string, bool, func } from 'prop-types';
// import classnames from 'classnames';

import { Flex, View, Avatar, Icon } from 'elfen';

// import { SingleImgView } from 'react-imageview';
import 'react-imageview/dist/react-imageview.min.css';

// import { getImagePrefix } from 'utils';

import classes from './index.less';

// const IMAGE = getImagePrefix();

export default class Image extends React.Component {
  static label = '图片卡片';
  static type = 'IMAGE';

  static propTypes = {
    banner: string.isRequired,
    client: bool,
    onSelect: func,
    animation: bool,
  };

  static defaultProps = {
    banner: 'http://obzxlsphd.bkt.clouddn.com//zzz/images/v2-953608ff58261bdf314d03996a995a8d_r.jpg',
    avatar: 'http://12292-zis-microservices-za-im-image.test.za.net/oss/file/1f10bd5b-ceeb-49d8-a49f-117155961bdc',
    client: false,
    onSelect: () => {},
    animation: true,
  };

  state = {
    progress: 0,
    error: false,
  };

  componentDidMount() {
    // if (this.props.client && this.props.uploadFile) {
    //   this.upload();
    // }
  }

  componentWillReceiveProps(nextProps) {
    if (this.props.src !== nextProps.src) {
      this.complete = true;
    }
  }

  shouldComponentUpdate(nextProps, nextState) {
    // console.log(this.props, nextProps, this.props === nextProps);
    // console.log(this.state, nextState, this.state === nextState);
    return this.props.src !== nextProps.src || this.state !== nextState;
  }


  // @TODO
  // complete = false;
  complete = true;

  handleClickImage = () => {
    // SingleImgView.show({
    //   maxScale: 3,
    //   imagelist: [this.props.src],
    //   close: () => SingleImgView.hide(),
    // });
  };

  replaceImage = (image) => {
    // this.props.onMessage('image:replace', this.props.dispatch, this.props.id, image);
    this.props.onMessage('image:replace', this.props.id, image);
  };

  upload = () => {
    const self = this;
    const replaceImage = this.replaceImage;
    const xhr = new XMLHttpRequest(); // eslint-disable-line
    // xhr.open('POST', 'http://12292-zis-microservices-za-im-image.test.za.net/oss/file/upload/', true);
    // xhr.open('POST', `${IMAGE}/upload/`, true);
    xhr.onload = () => {};

    xhr.onerror = () => {
      this.setState({ error: true });
    };

    xhr.onreadystatechange = function onreadystatechange() {
      if (this.readyState !== 4) {
        return;
      }

      if (this.status === 200) {
        const json = JSON.parse(xhr.responseText);
        // replaceImage(`http://12292-zis-microservices-za-im-image.test.za.net/oss/file/${json.token}`);
        // replaceImage(`${IMAGE}/${json.token}`);
      } else {
        self.setState({ error: true });
      }
    };

    // disable progress
    // xhr.upload.onprogress = (e) => {
    //   if (e.lengthComputable) {
    //     this.setState({ progress: (e.loaded / e.total) * 100 });
    //   }
    // };

    const formData = new FormData(); // eslint-disable-line
    formData.append('file', this.props.uploadFile);
    xhr.send(formData);
  };

  count = 1;

  render() {
    const { error, progress } = this.state;
    const { client, banner, animation, onSelect } = this.props;
    const flow = client ? 'row-reverse' : 'row';
    const avatarClass = client ? classes.avatarClient : classes.avatar;

    return (
      <Flex className={classes.root} align="flex-start" justify="flex-start" flow={flow} onClick={onSelect}>
        <View style={{ position: 'relative' }} className={classes.wrapper}>
          <img
            className={classes.image}
            style={{
              zIndex: 1,
              filter: !this.complete ? 'blur(4px)' : 'blur(0px)',
              transition: 'filter .7s cubic-bezier(1, 0.1, 1, 1)',
            }}
            role="presentation"
            src={banner}
            onClick={this.handleClickImage}
            onLoad={this.props.onLoad}
          />
          <div
            style={{
              flex: 1,
              position: 'absolute',
              pointerEvents: 'none',
              height: `${progress}%`,
              transition: 'all .3s ease',
              opacity: animation && (progress !== 100) ? 1 : 0,
            }}
            className={classes.mask}
          />
          {!error ? (<div
            style={{
              position: 'absolute',
              opacity: animation && (progress !== 100) ? 1 : 0,
              pointerEvents: this.props.uploadFile && animation && (progress !== 100) ? 'auto' : 'none',
            }}
            className={classes.data}
          >
            {/* parseInt(progress, 10) */}
          </div>) : (
            <div
              style={{
                position: 'absolute',
                opacity: 1,
                backgroundColor: 'rgba(0, 0, 0, .38)',
                pointerEvents: this.props.uploadFile && (progress !== 100) ? 'auto' : 'none',
              }}
              className={classes.data}
            >
              <Icon name="error" color="#F76260" size={64} />
            </div>
          )}
        </View>
      </Flex>
    );
  }
}